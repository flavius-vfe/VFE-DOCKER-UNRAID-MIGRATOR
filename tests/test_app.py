import importlib.util
import json
import os
import shutil
import socket
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("migrator", Path(__file__).parents[1] / "app.py")
m = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(m)


class MigratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.patches = [
            patch.object(m, "DATA_DIR", root / "data"),
            patch.object(m, "STATE_FILE", root / "data" / "state.json"),
            patch.object(m, "SESSION_KEY_FILE", root / "data" / "session.key"),
            patch.object(m, "JOBS_DIR", root / "data" / "jobs"),
            patch.object(m, "TMP_DIR", root / "data" / "tmp"),
            patch.object(m, "RSYNC_DIR", root / "data" / "rsync"),
            patch.object(m, "HOST_PREFIX", root / "host"),
            patch.object(m, "SELF_CONTAINER_ID", ""),
        ]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)
        (root / "host" / "mnt" / "user" / "appdata").mkdir(parents=True)
        (root / "host" / "var" / "lib" / "docker" / "volumes").mkdir(parents=True)
        with m.IMAGE_TASKS_LOCK:
            m.IMAGE_TASKS.clear()

    def test_session_round_trip(self):
        token, csrf = m.create_session()
        payload = m.verify_session(token)
        self.assertIsNotNone(payload)
        self.assertEqual(payload["csrf"], csrf)
        self.assertIsNone(m.verify_session(token + "x"))

    def test_host_path_translation_and_rejection(self):
        local = m.host_to_local("/mnt/user/appdata/demo")
        self.assertTrue(str(local).endswith("host/mnt/user/appdata/demo"))
        with self.assertRaises(m.AppError):
            m.host_to_local("/etc/shadow")
        with self.assertRaises(m.AppError):
            m.host_to_local("/mnt")

    def test_peer_signature_changes_with_body(self):
        first = m.peer_signature("secret", "POST", "/peer/test", "123", "nonce", "aaa")
        second = m.peer_signature("secret", "POST", "/peer/test", "123", "nonce", "bbb")
        self.assertNotEqual(first, second)
        self.assertEqual(first, m.peer_signature("secret", "POST", "/peer/test", "123", "nonce", "aaa"))

    def test_pair_code_is_one_time(self):
        generated = m.generate_pair_code()
        m.consume_pair_code(generated["code"])
        with self.assertRaises(m.PeerError):
            m.consume_pair_code(generated["code"])

    def sample_inspect(self):
        return {
            "Id": "a" * 64,
            "Name": "/demo",
            "Config": {
                "Image": "example/demo:latest",
                "Env": ["MODE=prod"],
                "Cmd": ["run"],
                "Entrypoint": ["/entrypoint"],
                "Labels": {"net.unraid.docker.webui": "http://[IP]:[PORT:8080]"},
                "ExposedPorts": {"8080/tcp": {}},
                "Hostname": "a" * 12,
            },
            "HostConfig": {
                "Binds": ["/old:/config:rw"],
                "PortBindings": {"8080/tcp": [{"HostIp": "", "HostPort": "8080"}]},
                "RestartPolicy": {"Name": "unless-stopped", "MaximumRetryCount": 0},
                "NetworkMode": "br0",
                "Privileged": False,
                "Links": ["old:old"],
                "VolumesFrom": ["old"],
                "AutoRemove": False,
            },
        }

    def test_container_payload_rewrites_paths_ports_and_network(self):
        inspect = self.sample_inspect()
        plan = {
            "image": "example/demo:latest",
            "ports": [{"target": "8080", "protocol": "tcp", "host_ip": "", "destination_host_port": "8180"}],
            "network": {"mode": "br0", "ipv4_address": "192.168.1.50", "aliases": ["demo"]},
        }
        mounts = [{"type": "bind", "destination_path": "/mnt/user/appdata/demo", "target": "/config", "mode": "rw"}]
        payload = m.build_container_payload(inspect, plan, mounts)
        self.assertEqual(payload["HostConfig"]["Binds"], ["/mnt/user/appdata/demo:/config:rw"])
        self.assertEqual(payload["HostConfig"]["PortBindings"]["8080/tcp"][0]["HostPort"], "8180")
        self.assertEqual(payload["NetworkingConfig"]["EndpointsConfig"]["br0"]["IPAMConfig"]["IPv4Address"], "192.168.1.50")
        self.assertNotIn("Links", payload["HostConfig"])
        self.assertNotIn("VolumesFrom", payload["HostConfig"])

    def test_template_rewrite(self):
        source = """<?xml version='1.0'?>
<Container version='2'>
  <Name>demo</Name><Repository>old/image</Repository><Network>bridge</Network><MyIP/>
  <Config Name='Config' Target='/config' Default='/old' Mode='rw' Description='' Type='Path' Display='always' Required='true' Mask='false'>/old</Config>
  <Config Name='Port' Target='8080' Default='8080' Mode='tcp' Description='' Type='Port' Display='always' Required='false' Mask='false'>8080</Config>
</Container>"""
        plan = {
            "destination_name": "demo-new",
            "image": "new/image:latest",
            "network": {"mode": "br0", "ipv4_address": "192.168.1.51"},
            "ports": [{"target": "8080", "protocol": "tcp", "destination_host_port": "8180"}],
        }
        mounts = [{"type": "bind", "target": "/config", "destination_path": "/mnt/user/appdata/demo-new", "mode": "rw"}]
        result = m.rewrite_unraid_template(source, plan, mounts)
        root = m.ET.fromstring(result)
        self.assertEqual(root.findtext("Name"), "demo-new")
        self.assertEqual(root.findtext("Repository"), "new/image:latest")
        configs = {node.attrib["Type"]: node for node in root.findall("Config")}
        self.assertEqual(configs["Path"].text, "/mnt/user/appdata/demo-new")
        self.assertEqual(configs["Port"].text, "8180")

    def test_job_lifecycle_persistence(self):
        job = m.create_job({"container_name": "demo"})
        updated = m.update_job(job["id"], status="running", progress_percent=50)
        m.job_log(job["id"], "halfway")
        loaded = m.load_job(job["id"])
        self.assertEqual(updated["status"], "running")
        self.assertEqual(loaded["progress_percent"], 50)
        self.assertEqual(loaded["logs"][-1]["message"], "halfway")

    def test_minimal_template_is_valid_xml(self):
        plan = {
            "destination_name": "demo",
            "image": "example/demo:latest",
            "network": {"mode": "bridge", "ipv4_address": ""},
            "ports": [],
            "privileged": False,
        }
        xml_text = m.minimal_unraid_template(plan, [])
        root = m.ET.fromstring(xml_text)
        self.assertEqual(root.tag, "Container")
        self.assertEqual(root.attrib["version"], "2")

    def test_ipv4_validation(self):
        self.assertEqual(m.validate_ipv4("192.168.1.10"), "192.168.1.10")
        with self.assertRaises(m.AppError):
            m.validate_ipv4("server.local")
        with self.assertRaises(m.AppError):
            m.validate_ipv4("2001:db8::1")

    def test_preflight_accepts_empty_destination(self):
        class FakeDocker:
            def containers(self): return []
            def inspect_volume(self, name): return None
            def inspect_network(self, name): return {"Containers": {}} if name == "br0" else None
            def inspect_image(self, image): return {"Id": "image"}
        plan = {
            "destination_name": "demo",
            "image": "example/demo:latest",
            "image_mode": "existing",
            "existing_image": "example/demo:latest",
            "mounts": [{
                "selected": True, "supported": True, "exists": True, "type": "bind",
                "source": "/mnt/user/appdata/source", "destination_path": "/mnt/user/appdata/destination",
                "size_bytes": 100,
            }],
            "ports": [{"destination_host_port": "8180", "protocol": "tcp", "host_ip": ""}],
            "network": {"mode": "br0", "ipv4_address": "192.168.1.50", "create_if_missing": False},
            "devices": [],
        }
        with patch.object(m, "DockerClient", FakeDocker), patch.object(m, "published_ports_in_use", return_value=set()):
            result = m.destination_preflight(plan)
        self.assertTrue(result["ok"], result)


    def test_image_prepare_skips_pull_when_present(self):
        class FakeDocker:
            def inspect_image(self, image): return {"Id": "present"}
            def pull_image(self, image, log_callback=None, timeout=0):
                raise AssertionError("pull must not run")
        with patch.object(m, "DockerClient", FakeDocker):
            result = m.start_image_ensure_task("example/demo:latest", "pull_source")
        self.assertEqual(result["status"], "complete")
        self.assertTrue(result["already_present"])

    def test_image_prepare_reports_background_pull_completion(self):
        class FakeDocker:
            ready = False
            def inspect_image(self, image):
                return {"Id": "sha256:new-image"} if self.ready else None
            def pull_image(self, image, log_callback=None, timeout=0):
                if log_callback:
                    log_callback("Downloading layer")
                type(self).ready = True
        with patch.object(m, "DockerClient", FakeDocker):
            result = m.start_image_ensure_task("example/demo:latest", "pull_source")
            task_id = result["task_id"]
            snapshot = {}
            for _ in range(50):
                snapshot = m._image_task_snapshot(task_id)
                if snapshot["status"] != "pulling":
                    break
                time.sleep(0.01)
        self.assertEqual(snapshot["status"], "complete")
        self.assertIn("ready", snapshot["message"].lower())


    def test_remove_image_if_unused_deletes_exact_image(self):
        client = object.__new__(m.DockerClient)
        with patch.object(client, "inspect_image", return_value={"Id": "sha256:abc"}), \
             patch.object(client, "containers", return_value=[]), \
             patch.object(client, "request", return_value=(200, {}, b"[]")) as request:
            result = client.remove_image_if_unused("example/demo:latest", "sha256:abc")
        self.assertTrue(result["removed"])
        self.assertIn("/images/sha256%3Aabc", request.call_args.args[1])

    def test_remove_image_if_unused_keeps_referenced_image(self):
        client = object.__new__(m.DockerClient)
        containers = [{"ImageID": "sha256:abc", "Names": ["/demo"]}]
        with patch.object(client, "inspect_image", return_value={"Id": "sha256:abc"}), \
             patch.object(client, "containers", return_value=containers), \
             patch.object(client, "request") as request:
            result = client.remove_image_if_unused("example/demo:latest", "sha256:abc")
        self.assertFalse(result["removed"])
        self.assertEqual(result["reason"], "in-use")
        request.assert_not_called()

    def test_image_prepare_reuses_active_pull(self):
        import threading
        release = threading.Event()

        class FakeDocker:
            ready = False
            def inspect_image(self, image):
                return {"Id": "sha256:ready"} if type(self).ready else None
            def pull_image(self, image, log_callback=None, timeout=0):
                release.wait(1)
                type(self).ready = True

        with patch.object(m, "DockerClient", FakeDocker):
            first = m.start_image_ensure_task("example/demo:latest", "pull_source")
            second = m.start_image_ensure_task("example/demo:latest", "pull_source")
            self.assertEqual(first["task_id"], second["task_id"])
            self.assertTrue(second.get("reused"))
            release.set()
            for _ in range(100):
                if m._image_task_snapshot(first["task_id"])["status"] != "pulling":
                    break
                time.sleep(0.01)
            self.assertEqual(m._image_task_snapshot(first["task_id"])["status"], "complete")

    def test_duplicate_active_migration_is_rejected(self):
        plan = {
            "source_server_id": "source",
            "destination_server_id": "destination",
            "container_id": "a" * 64,
            "destination_name": "demo",
            "image_mode": "existing",
        }
        active = {
            "id": "existing-job",
            "status": "running",
            "plan": dict(plan),
            "created_at": "2026-01-01T00:00:00+00:00",
        }
        with patch.object(m, "load_state", return_value={"server_id": "source", "lan_ip": "192.168.1.10"}), \
             patch.object(m, "get_peer", return_value={"lan_ip": "192.168.1.11"}), \
             patch.object(m, "signed_peer_json", return_value={"migration_protocol_version": m.MIGRATION_PROTOCOL_VERSION}), \
             patch.object(m, "list_jobs", return_value=[active]), \
             patch.object(m, "create_job") as create_job:
            with self.assertRaises(m.AppError) as raised:
                m.start_local_migration(plan)
        self.assertEqual(raised.exception.status, 409)
        create_job.assert_not_called()

    @unittest.skipUnless(shutil.which("rsync"), "rsync is not installed")
    def test_rsync_transfer_integration(self):
        source = m.HOST_PREFIX / "mnt" / "source"
        destination = m.HOST_PREFIX / "mnt" / "destination"
        (source / "sub").mkdir(parents=True)
        destination.mkdir(parents=True)
        (source / "one.txt").write_text("one", encoding="utf-8")
        (source / "sub" / "two.txt").write_text("two", encoding="utf-8")
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        with patch.object(m, "RSYNC_PORT", port):
            receiver = m.start_rsync_daemon("integration", "/mnt/destination", "127.0.0.1")
            try:
                m.run_rsync("/mnt/source", receiver, "127.0.0.1", final_pass=True)
            finally:
                m.stop_rsync_daemon("integration")
        self.assertEqual((destination / "one.txt").read_text(encoding="utf-8"), "one")
        self.assertEqual((destination / "sub" / "two.txt").read_text(encoding="utf-8"), "two")

    def test_untagged_pull_reference_defaults_to_latest(self):
        self.assertEqual(m.normalize_pull_reference("searxng/searxng"), "searxng/searxng:latest")
        self.assertEqual(
            m.normalize_pull_reference("registry.local:5000/team/app"),
            "registry.local:5000/team/app:latest",
        )
        self.assertEqual(
            m.normalize_pull_reference("registry.local:5000/team/app:v2"),
            "registry.local:5000/team/app:v2",
        )
        self.assertEqual(
            m.normalize_pull_reference("team/app@sha256:" + "a" * 64),
            "team/app@sha256:" + "a" * 64,
        )

    def test_pull_image_never_sends_an_empty_tag(self):
        class FakeResponse:
            status = 200
            def readline(self): return b""

        class FakeConnection:
            def __init__(self): self.path = ""
            def request(self, method, path, headers=None): self.path = path
            def getresponse(self): return FakeResponse()
            def close(self): pass

        client = object.__new__(m.DockerClient)
        connection = FakeConnection()
        with patch.object(client, "_connection", return_value=connection):
            result = client.pull_image("searxng/searxng")
        self.assertEqual(result, "searxng/searxng:latest")
        self.assertIn("fromImage=searxng%2Fsearxng%3Alatest", connection.path)



    def test_custom_image_requires_explicit_tag(self):
        plan = {"image_mode": "pull_custom", "custom_image": "example/demo", "source_image": "old/demo:1"}
        with self.assertRaises(m.AppError):
            m.destination_image_reference(plan)
        plan["custom_image"] = "example/demo:stable"
        self.assertEqual(m.destination_image_reference(plan), "example/demo:stable")

    def test_preflight_path_conflict_returns_resolution_actions(self):
        destination = m.HOST_PREFIX / "mnt" / "user" / "appdata" / "destination"
        destination.mkdir(parents=True)
        (destination / "existing.txt").write_text("old", encoding="utf-8")

        class FakeDocker:
            def containers(self): return []
            def inspect_volume(self, name): return None
            def inspect_network(self, name): return None
            def inspect_image(self, image): return {"Id": "image"}

        plan = {
            "destination_name": "demo",
            "source_image": "example/demo:latest",
            "image_mode": "pull_source",
            "mounts": [{
                "id": "mount-0", "selected": True, "supported": True, "exists": True,
                "type": "bind", "source": "/mnt/user/appdata/source",
                "destination_path": "/mnt/user/appdata/destination", "size_bytes": 10,
            }],
            "ports": [], "network": {"mode": "bridge"}, "devices": [],
        }
        with patch.object(m, "DockerClient", FakeDocker), patch.object(m, "published_ports_in_use", return_value=set()):
            result = m.destination_preflight(plan)
        issue = next(item for item in result["issues"] if item["code"] == "path_not_empty")
        self.assertEqual({action["id"] for action in issue["actions"]}, {"path_merge", "path_replace", "path_change"})

    def test_preflight_path_merge_resolves_conflict(self):
        destination = m.HOST_PREFIX / "mnt" / "user" / "appdata" / "destination"
        destination.mkdir(parents=True)
        (destination / "existing.txt").write_text("old", encoding="utf-8")

        class FakeDocker:
            def containers(self): return []
            def inspect_volume(self, name): return None
            def inspect_network(self, name): return None
            def inspect_image(self, image): return {"Id": "image"}

        plan = {
            "destination_name": "demo", "source_image": "example/demo:latest", "image_mode": "pull_source",
            "mounts": [{
                "id": "mount-0", "selected": True, "supported": True, "exists": True,
                "type": "bind", "source": "/mnt/user/appdata/source",
                "destination_path": "/mnt/user/appdata/destination", "size_bytes": 10,
                "existing_policy": "merge",
            }],
            "ports": [], "network": {"mode": "bridge"}, "devices": [],
        }
        with patch.object(m, "DockerClient", FakeDocker), patch.object(m, "published_ports_in_use", return_value=set()):
            result = m.destination_preflight(plan)
        self.assertTrue(result["ok"], result)
        self.assertTrue(any(item["code"] == "path_merge" for item in result["warnings"]))

    def test_preflight_volume_conflict_returns_four_actions(self):
        class FakeDocker:
            def containers(self): return []
            def inspect_volume(self, name): return {"Name": name, "Mountpoint": "/var/lib/docker/volumes/demo/_data"}
            def inspect_network(self, name): return None
            def inspect_image(self, image): return {"Id": "image"}
        plan = {
            "destination_name": "demo", "source_image": "example/demo:latest", "image_mode": "pull_source",
            "mounts": [{
                "id": "mount-0", "selected": True, "supported": True, "exists": True,
                "type": "volume", "source": "/var/lib/docker/volumes/source/_data",
                "destination_volume": "demo-data", "size_bytes": 1,
            }],
            "ports": [], "network": {"mode": "bridge"}, "devices": [],
        }
        with patch.object(m, "DockerClient", FakeDocker), patch.object(m, "published_ports_in_use", return_value=set()):
            result = m.destination_preflight(plan)
        issue = next(item for item in result["issues"] if item["code"] == "volume_exists")
        self.assertEqual(
            {action["id"] for action in issue["actions"]},
            {"volume_merge", "volume_replace", "volume_skip", "volume_rename"},
        )

    def test_prepare_bind_replace_clears_destination(self):
        destination = m.HOST_PREFIX / "mnt" / "user" / "appdata" / "destination"
        destination.mkdir(parents=True)
        (destination / "old.txt").write_text("old", encoding="utf-8")
        plan = {"mounts": [{
            "selected": True, "type": "bind", "destination_path": "/mnt/user/appdata/destination",
            "existing_policy": "replace", "destructive_confirmed": True, "is_file": False,
        }]}
        with patch.object(m, "DockerClient"):
            prepared = m.prepare_destination_storage(plan)
        self.assertEqual(list(destination.iterdir()), [])
        self.assertTrue(prepared[0]["transfer_data"])

    def test_prepare_existing_volume_skip_does_not_transfer_data(self):
        class FakeDocker:
            def inspect_volume(self, name):
                return {"Name": name, "Mountpoint": "/var/lib/docker/volumes/demo-data/_data"}
            def create_volume(self, name): raise AssertionError("must not create")
        plan = {"mounts": [{
            "selected": True, "type": "volume", "destination_volume": "demo-data", "existing_policy": "skip",
        }]}
        with patch.object(m, "DockerClient", FakeDocker):
            prepared = m.prepare_destination_storage(plan)
        self.assertFalse(prepared[0]["transfer_data"])

    def test_container_payload_removes_skipped_device(self):
        inspect = self.sample_inspect()
        inspect["HostConfig"]["Devices"] = [{"PathOnHost": "/dev/old", "PathInContainer": "/dev/old", "CgroupPermissions": "rwm"}]
        plan = {
            "image": "example/demo:latest", "resolved_image": "sha256:" + "b" * 64,
            "ports": [], "network": {"mode": "bridge"},
            "devices": [
                {"source": "/dev/dri", "target": "/dev/dri", "permissions": "rwm", "selected": True},
                {"source": "/dev/skip", "target": "/dev/skip", "permissions": "rwm", "selected": False},
            ],
        }
        payload = m.build_container_payload(inspect, plan, [])
        self.assertEqual(payload["Image"], "sha256:" + "b" * 64)
        self.assertEqual(payload["HostConfig"]["Devices"], [{"PathOnHost": "/dev/dri", "PathInContainer": "/dev/dri", "CgroupPermissions": "rwm"}])

    def test_source_repository_quick_image_references(self):
        self.assertEqual(m.image_repository("qmcgaw/gluetun"), "qmcgaw/gluetun")
        self.assertEqual(m.image_repository("qmcgaw/gluetun:stable"), "qmcgaw/gluetun")
        self.assertEqual(
            m.image_repository("registry.local:5000/team/app:v2"),
            "registry.local:5000/team/app",
        )
        self.assertEqual(
            m.image_repository("team/app@sha256:" + "a" * 64),
            "team/app",
        )

    def test_three_source_repository_quick_modes(self):
        base = {"source_image": "qmcgaw/gluetun"}
        self.assertEqual(
            m.destination_image_reference({**base, "image_mode": "pull_configured"}),
            "qmcgaw/gluetun:latest",
        )
        self.assertEqual(
            m.destination_image_reference({**base, "image_mode": "pull_latest"}),
            "qmcgaw/gluetun:latest",
        )
        self.assertEqual(
            m.destination_image_reference({**base, "image_mode": "pull_stable"}),
            "qmcgaw/gluetun:stable",
        )

    def test_configured_quick_mode_preserves_explicit_source_tag(self):
        plan = {"source_image": "qmcgaw/gluetun:v3.40", "image_mode": "pull_configured"}
        self.assertEqual(m.destination_image_reference(plan), "qmcgaw/gluetun:v3.40")

    def test_exact_image_transfer_uses_rsync_channel(self):
        image_id = "sha256:" + "a" * 64
        calls = []

        class FakeDocker:
            def save_image(self, image, destination, progress_callback=None):
                self.assert_image = image
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(b"exact-image-archive")
                if progress_callback:
                    progress_callback(destination.stat().st_size)

        def fake_destination_call(plan, path, payload=None, method="POST", timeout=m.PEER_TIMEOUT):
            calls.append((path, payload or {}))
            if path == "/peer/image/transfer/start":
                return {
                    "module": "migration_test",
                    "username": "migrator",
                    "password": "secret",
                    "port": 8211,
                    "target_suffix": "image.tar",
                    "resume_bytes": 0,
                }
            if path == "/peer/rsync/stop":
                return {"ok": True}
            if path == "/peer/image/transfer/load":
                self.assertEqual(payload["image"], image_id)
                self.assertEqual(payload["size"], len(b"exact-image-archive"))
                return {"image_id": image_id, "created_by_job": True}
            raise AssertionError(path)

        state = m.load_state()
        peer_id = "peer-1"
        state["peers"][peer_id] = {
            "server_id": peer_id,
            "lan_ip": "127.0.0.1",
            "url": "http://127.0.0.1:8210",
            "secret": "secret",
        }
        m.save_state(state)
        job = m.create_job({"container_name": "demo"})
        plan = {"destination_server_id": peer_id, "source_image_id": image_id}

        with patch.object(m, "DockerClient", FakeDocker), \
             patch.object(m, "destination_call", side_effect=fake_destination_call), \
             patch.object(m, "run_rsync_local_path") as rsync_mock:
            result = m.transfer_image_to_peer(job["id"], plan)

        self.assertEqual(result, image_id)
        rsync_mock.assert_called_once()
        self.assertEqual([item[0] for item in calls], [
            "/peer/image/transfer/start",
            "/peer/rsync/stop",
            "/peer/image/transfer/load",
        ])

    def test_load_transferred_image_validates_and_removes_archive(self):
        job_id = "job-exact-image"
        image_id = "sha256:" + "b" * 64
        archive = m.incoming_image_path(job_id)
        archive.parent.mkdir(parents=True, exist_ok=True)
        archive.write_bytes(b"docker-image")
        expected_hash = m.hashlib.sha256(b"docker-image").hexdigest()

        class FakeDocker:
            loaded = False
            def inspect_image(self, image):
                return {"Id": image_id} if self.loaded else None
            def load_image(self, source, log_callback=None):
                self.assert_source = source
                type(self).loaded = True

        with patch.object(m, "DockerClient", FakeDocker):
            result = m.load_transferred_image(job_id, image_id, expected_hash, len(b"docker-image"))

        self.assertEqual(result["image_id"], image_id)
        self.assertTrue(result["created_by_job"])
        self.assertFalse(archive.exists())


if __name__ == "__main__":
    unittest.main()
