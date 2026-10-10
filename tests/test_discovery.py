import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import contextlib, io, json, tempfile, unittest
from pathlib import Path
from unittest.mock import Mock, patch
from docker_update_manager.docker import _version, discover
from docker_update_manager.registry import scan_service, scan_service_with_tracking, tracking_image
from docker_update_manager.models import Service
from docker_update_manager.state import State
from docker_update_manager.cli import actionable_updates, execute, parser
from docker_update_manager.config import Config
from docker_update_manager.progress import Reporter
from docker_update_manager.operations import do_update, PreMutationRefusal

C={"Id":"c1","Name":"/sonarr","Image":"i1","Config":{"Image":"lscr.io/linuxserver/sonarr:latest","Labels":{"com.docker.compose.project":"media","com.docker.compose.service":"sonarr","com.docker.compose.project.working_dir":"/opt/media","com.docker.compose.project.config_files":"/opt/media/compose.yml,/opt/media/override.yml"}},"State":{"Status":"running","StartedAt":"x","Health":{"Status":"healthy"}},"HostConfig":{"RestartPolicy":{"Name":"unless-stopped"}}}
I={"Id":"i1","RepoDigests":["lscr.io/linuxserver/sonarr@sha256:"+"a"*64],"Created":"x","Architecture":"amd64","Config":{"Labels":{"org.opencontainers.image.version":"4.0.15"}}}

class DiscoveryTests(unittest.TestCase):
    def test_missing_repo_digests_is_unverified_not_local_build(self):
        for metadata in ({}, {"RepoDigests": []}, {"RepoDigests": None}):
            for compose in (True, False):
                with self.subTest(metadata=metadata, compose=compose):
                    c=json.loads(json.dumps(C)); c["Config"]["Image"]="docker.io/prom/prometheus"
                    if not compose: c["Config"]["Labels"]={}
                    image={key: value for key, value in I.items() if key != "RepoDigests"}
                    image.update(metadata)
                    with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([c]), json.dumps([image])]):
                        service=discover()[0]
                    self.assertFalse(service.local_build)
                    self.assertIsNone(service.digest)
                    remote={"digest": "sha256:"+"b"*64, "platforms": [], "version": None, "created": None}
                    with patch("docker_update_manager.registry.remote_manifest", return_value=remote):
                        result=scan_service(service)
                        accepted, _=actionable_updates([service], None)
                    self.assertEqual(result.status, "UNKNOWN")
                    self.assertEqual(result.error, "Local repository digest is unavailable; update comparison is unverified.")
                    self.assertEqual(accepted, [])

    def _containerd_image(self, **changes):
        # Synthetic shape of a dangling containerd-store image: no RepoDigests,
        # target descriptor digest equal to Id, Identity binding the pull repo.
        image_id="sha256:"+"c"*64
        image={"Id": image_id, "RepoTags": [], "RepoDigests": [], "Architecture": "amd64", "Config": {"Labels": {}},
               "Descriptor": {"mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
                              "digest": image_id, "size": 2010},
               "Identity": {"Pull": [{"Repository": "docker.io/prom/prometheus"}]}}
        image.update(changes)
        return image

    def _discover_with(self, image, configured="prom/prometheus:latest"):
        c=json.loads(json.dumps(C)); c["Image"]=image["Id"] if isinstance(image.get("Id"), str) else "i1"
        c["Config"]["Image"]=configured
        with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([c]), json.dumps([image])]):
            return discover()[0]

    def test_containerd_descriptor_bound_to_repository_and_image_id_is_local_digest(self):
        image=self._containerd_image()
        for configured in ("prom/prometheus:latest", "docker.io/prom/prometheus:3",
                           "prom/prometheus:latest@"+image["Id"]):
            with self.subTest(configured=configured):
                service=self._discover_with(image, configured)
                self.assertEqual(service.digest, image["Id"])
        service=self._discover_with(image)
        for remote, expected in ((image["Id"], "CURRENT"), ("sha256:"+"b"*64, "DIGEST CHANGED")):
            with self.subTest(expected=expected), patch("docker_update_manager.registry.remote_manifest", return_value={
                    "digest": remote, "platforms": [], "version": None, "created": None}):
                self.assertEqual(scan_service(service).status, expected)

    def test_unproven_containerd_provenance_stays_unknown(self):
        base=self._containerd_image()
        other="sha256:"+"d"*64
        cases={
            "other repository": dict(Identity={"Pull": [{"Repository": "docker.io/grafana/grafana"}]}),
            "no identity": dict(Identity=None),
            "empty pull": dict(Identity={"Pull": []}),
            "malformed pull": dict(Identity={"Pull": [{"Repository": "docker.io/prom/prometheus:latest"}]}),
            "malformed pull entry": dict(Identity={"Pull": ["docker.io/prom/prometheus"]}),
            "descriptor differs from image id": dict(Descriptor=dict(base["Descriptor"], digest=other)),
            "config media type": dict(Descriptor=dict(base["Descriptor"], mediaType="application/vnd.oci.image.config.v1+json")),
            "malformed digest": dict(Id="sha256:short", Descriptor=dict(base["Descriptor"], digest="sha256:short")),
            "no descriptor": dict(Descriptor=None),
        }
        for name, changes in cases.items():
            with self.subTest(name):
                self.assertIsNone(self._discover_with(self._containerd_image(**changes)).digest)
        with self.subTest("conflicting configured pin"):
            self.assertIsNone(self._discover_with(base, "prom/prometheus@"+other).digest)
        with self.subTest("different running image id"):
            c=json.loads(json.dumps(C)); c["Image"]=other; c["Config"]["Image"]="prom/prometheus:latest"
            with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([c]), json.dumps([base])]):
                service=discover()[0]
            self.assertIsNone(service.digest)
        service=self._discover_with(self._containerd_image(Identity=None))
        with patch("docker_update_manager.registry.remote_manifest", return_value={
                "digest": base["Id"], "platforms": [], "version": None, "created": None}):
            result=scan_service(service)
        self.assertEqual((result.status, result.error),
                         ("UNKNOWN", "Local repository digest is unavailable; update comparison is unverified."))

    def test_repo_digests_are_bound_to_the_configured_repository(self):
        a, b = "sha256:"+"a"*64, "sha256:"+"b"*64
        image=lambda *entries: self._containerd_image(RepoDigests=list(entries))
        cases=(
            ("matching", ["prom/prometheus@"+a], "prom/prometheus:latest", a),
            ("matching among other repositories", ["grafana/grafana@"+b, "docker.io/prom/prometheus@"+a], "prom/prometheus:latest", a),
            ("duplicate same digest", ["prom/prometheus@"+a, "docker.io/prom/prometheus@"+a], "prom/prometheus:latest", a),
            ("agreeing pin", ["prom/prometheus@"+a], "prom/prometheus:latest@"+a, a),
            ("only another repository", ["grafana/grafana@"+a], "prom/prometheus:latest", None),
            ("conflicting matching digests", ["prom/prometheus@"+a, "docker.io/prom/prometheus@"+b], "prom/prometheus:latest", None),
            ("pin disagrees", ["prom/prometheus@"+a], "prom/prometheus:latest@"+b, None),
            ("malformed entry", ["prom/prometheus@"+a, "prom/prometheus"], "prom/prometheus:latest", None),
            ("malformed digest", ["prom/prometheus@sha256:short"], "prom/prometheus:latest", None),
            ("non-string entry", [None], "prom/prometheus:latest", None),
        )
        for name, entries, configured, expected in cases:
            with self.subTest(name):
                self.assertEqual(self._discover_with(image(*entries), configured).digest, expected)
        with self.subTest("RepoDigests not a list"):
            self.assertIsNone(self._discover_with(self._containerd_image(RepoDigests="prom/prometheus@"+a)).digest)

    def test_descriptor_never_overrides_contradictory_repo_digests(self):
        other="sha256:"+"e"*64
        # The descriptor and Identity would prove the configured repository, but
        # RepoDigests contradicts them, so provenance stays unproven.
        for entries in (["grafana/grafana@"+other], ["prom/prometheus@"+other, "prom/prometheus@sha256:"+"f"*64]):
            with self.subTest(entries=entries):
                self.assertIsNone(self._discover_with(self._containerd_image(RepoDigests=entries)).digest)

    def test_missing_local_digest_never_compares_version_or_tracked_pin(self):
        with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([C]), json.dumps([I])]):
            service=discover()[0]
        service.digest=None
        for image in ("docker.io/prom/prometheus:3.0", "docker.io/prom/prometheus:latest@sha256:"+"a"*64):
            with self.subTest(image=image), patch("docker_update_manager.registry.remote_manifest", return_value={
                    "digest": "sha256:"+"a"*64, "platforms": [], "version": None, "created": None}):
                service.image=image
                self.assertEqual(scan_service(service, tracking_image(service)).status, "UNKNOWN")

    def test_valid_local_digest_equality_and_mismatch(self):
        with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([C]), json.dumps([I])]):
            service=discover()[0]
        for image, equal, expected in ((C["Config"]["Image"], True, "CURRENT"),
                (C["Config"]["Image"], False, "DIGEST CHANGED"),
                ("docker.io/prom/prometheus:3.0", False, "UPDATE"),
                ("docker.io/prom/prometheus:latest@sha256:"+"a"*64, True, "PINNED"),
                ("docker.io/prom/prometheus:latest@sha256:"+"a"*64, False, "PINNED UPDATE")):
            with self.subTest(expected=expected), patch("docker_update_manager.registry.remote_manifest", return_value={
                    "digest": "sha256:"+("a" if equal else "b")*64, "platforms": [], "version": None, "created": None}):
                service.image=image
                self.assertEqual(scan_service(service, tracking_image(service)).status, expected)

    def test_missing_digest_preserves_registry_architecture_and_channel_failures(self):
        with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([C]), json.dumps([I])]):
            service=discover()[0]
        service.digest=None
        with patch("docker_update_manager.registry.remote_manifest", side_effect=ValueError("rate limit")):
            self.assertEqual(scan_service(service).status, "REGISTRY ERROR")
        with patch("docker_update_manager.registry.remote_manifest", return_value={
                "digest": "sha256:"+"b"*64, "platforms": [{"os": "linux", "architecture": "arm64"}]}):
            self.assertEqual(scan_service(service).status, "ARCH UNSUPPORTED")
        service.image="docker.io/prom/prometheus@sha256:"+"a"*64
        with patch("docker_update_manager.registry.remote_manifest") as remote:
            self.assertEqual(scan_service(service).status, "UNTRACKED DIGEST")
            remote.assert_not_called()

    def test_explicit_update_without_digest_refuses_before_any_side_effect(self):
        with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([C]), json.dumps([I])]):
            service=discover()[0]
        for digest in (None, ""):
            for image in ("docker.io/prom/prometheus", "docker.io/prom/prometheus:latest@sha256:"+"a"*64):
                for dry_run in (False, True):
                    with self.subTest(digest=digest, image=image, dry_run=dry_run), \
                         patch("docker_update_manager.operations.run") as docker, \
                         patch("docker_update_manager.operations.run_compose_progress") as compose, \
                         patch("docker_update_manager.operations.backup_files") as backup, \
                         patch("docker_update_manager.operations.remote_manifest") as remote:
                        service.digest=digest; service.image=image
                        with self.assertRaises(PreMutationRefusal) as refused:
                            do_update(service, None, yes=True, dry_run=dry_run)
                        self.assertEqual(refused.exception.reason, "target_unavailable")
                        for call in (docker, compose, backup, remote): call.assert_not_called()

    def test_published_version_label_precedence_and_compatibility_labels(self):
        self.assertEqual(_version(
            {"org.opencontainers.image.version": "4.0.15", "version": "4.0.14"},
            {"org.opencontainers.image.version": "4.0.13"},
        ), "4.0.15")
        self.assertEqual(_version({"version": "3.2.1"}), "3.2.1")
        self.assertEqual(_version({"build_version": "version:-2.8.4 Build-date: 2026-09-01"}), "2.8.4")

    def test_compose_discovery(self):
        with patch("docker_update_manager.docker.run",side_effect=["c1\n",json.dumps([C]),json.dumps([I])]): s=discover()[0]
        self.assertEqual(s.stack,"media"); self.assertEqual(len(s.compose_files),2); self.assertEqual(s.version,"4.0.15")
    def test_standalone(self):
        c=json.loads(json.dumps(C)); c["Config"]["Labels"]={}
        with patch("docker_update_manager.docker.run",side_effect=["c1\n",json.dumps([c]),json.dumps([I])]): s=discover()[0]
        self.assertIsNone(s.stack)
    def test_compose_conventional_local_build(self):
        for name in ("media-sonarr", "media_sonarr:latest"):
            c=json.loads(json.dumps(C)); c["Config"]["Image"]=name
            image=dict(I, RepoDigests=[])
            with self.subTest(name=name), patch("docker_update_manager.docker.run",side_effect=["c1\n",json.dumps([c]),json.dumps([image])]):
                s=discover()[0]
            self.assertTrue(s.local_build)
            with patch("docker_update_manager.registry.remote_manifest") as remote:
                self.assertEqual(scan_service(s).status, "LOCAL BUILD")
                remote.assert_not_called()
    def test_registry_failure_not_current(self):
        with patch("docker_update_manager.registry.remote_manifest",side_effect=ValueError("rate limit")):
            with patch("docker_update_manager.docker.run",side_effect=["c1\n",json.dumps([C]),json.dumps([I])]): r=scan_service(discover()[0])
        self.assertEqual(r.status,"REGISTRY ERROR")
    def test_arch_mismatch(self):
        with patch("docker_update_manager.registry.remote_manifest",return_value={"digest":"sha256:b","platforms":[{"os":"linux","architecture":"arm64"}],"version":None,"created":None}):
            with patch("docker_update_manager.docker.run",side_effect=["c1\n",json.dumps([C]),json.dumps([I])]): r=scan_service(discover()[0])
        self.assertEqual(r.status,"ARCH UNSUPPORTED")
    def test_digest_changed(self):
        with patch("docker_update_manager.registry.remote_manifest",return_value={"digest":"sha256:b","platforms":[{"os":"linux","architecture":"amd64"}],"version":"4.0.16","created":None}):
            with patch("docker_update_manager.docker.run",side_effect=["c1\n",json.dumps([C]),json.dumps([I])]): r=scan_service(discover()[0])
        self.assertEqual(r.status,"DIGEST CHANGED")
    def test_digest_pin_tracks_explicit_tag_and_reports_update(self):
        s=Service("app","c","ghcr.io/x/app:stable@sha256:a","sha256:a","sha256:a",None,None,"amd64","running","none","no",None,"p","app","/x",["/x/c.yml"])
        with patch("docker_update_manager.registry.remote_manifest",return_value={"digest":"sha256:b","platforms":[],"version":"2.0","created":None}) as remote:
            r=scan_service(s,tracking_image(s))
        self.assertEqual(r.status,"PINNED UPDATE"); remote.assert_called_once_with("ghcr.io/x/app:stable")
    def test_digest_only_pin_recovers_channel_from_history(self):
        s=Service("app","c","ghcr.io/x/app@sha256:a","sha256:a","sha256:a",None,None,"amd64","running","none","no",None,"p","app","/x",["/x/c.yml"])
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); state.record(stack="p",service="app",action="convert",old_image="ghcr.io/x/app:beta",result="SUCCESS")
            self.assertEqual(tracking_image(s,state),"ghcr.io/x/app:beta")
    def test_duplicate_stack_service_names_keep_tracking_history_scoped(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t))
            state.record(stack="media",service="app",action="update",old_image="ghcr.io/x/app:stable",result="SUCCESS")
            state.record(stack="test",service="app",action="update",old_image="ghcr.io/x/app:beta",result="SUCCESS")
            service=Service("app","c","ghcr.io/x/app@sha256:a","sha256:a","sha256:a",None,None,"amd64","running","none","no",None,"test","app","/x",["/x/c.yml"])
            self.assertEqual(tracking_image(service,state),"ghcr.io/x/app:beta")
    def test_explicit_scoped_history_ignores_unprovable_legacy_namesake(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t))
            state.record(stack="media",service="app",action="update",old_image="ghcr.io/x/app:stable",result="SUCCESS")
            state.record(service="app",action="update",old_image="ghcr.io/x/app:beta",result="SUCCESS")
            service=Service("app","c","ghcr.io/x/app@sha256:a","sha256:a","sha256:a",None,None,"amd64","running","none","no",None,"media","app","/x",["/x/c.yml"])
            self.assertEqual(tracking_image(service,state),"ghcr.io/x/app:stable")
    def test_unscoped_legacy_history_fails_when_inventory_has_duplicate_names(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); state.record(service="app",action="update",old_image="ghcr.io/x/app:latest",result="SUCCESS")
            state.start_scan("inventory",total=2)
            state.stage_scan_result("inventory","complete",services=[
                {"service":{"stack":"media","compose_service":"app","key":"app","name":"app"},"status":"CURRENT"},
                {"service":{"stack":"test","compose_service":"app","key":"app","name":"app"},"status":"CURRENT"},
            ])
            state.mark_scan_terminal("inventory","complete",emit_event=False)
            service=Service("app","c","ghcr.io/x/app@sha256:a","sha256:a","sha256:a",None,None,"amd64","running","none","no",None,"test","app","/x",["/x/c.yml"])
            with self.assertRaisesRegex(ValueError,"legacy history.*no trustworthy stack metadata"):
                tracking_image(service,state)
            result=scan_service_with_tracking(service,state)
            self.assertEqual(result.status,"UNTRACKED DIGEST"); self.assertEqual(result.tracking_issue,"ambiguous_history")
    def test_unscoped_legacy_history_preserves_unique_stack_behavior(self):
        with tempfile.TemporaryDirectory() as t:
            state=State(Path(t)); backup=state.root/"backups"/"legacy"; backup.mkdir(parents=True)
            (backup/"metadata.json").write_text(json.dumps({"stack":"media","service":"app","files":[]}))
            state.record(service="app",action="convert",old_image="ghcr.io/x/app:beta",backup=str(backup),result="SUCCESS")
            state.start_scan("unique-inventory",total=1)
            state.stage_scan_result("unique-inventory","complete",services=[
                {"service":{"stack":"media","compose_service":"app","key":"app","name":"app"},"status":"CURRENT"},
            ])
            state.mark_scan_terminal("unique-inventory","complete",emit_event=False)
            service=Service("app","c","ghcr.io/x/app@sha256:a","sha256:a","sha256:a",None,None,"amd64","running","none","no",None,"media","app","/x",["/x/c.yml"])
            self.assertEqual(tracking_image(service,state),"ghcr.io/x/app:beta")
    def test_digest_only_pin_without_history_does_not_guess_latest(self):
        s=Service("app","c","ghcr.io/x/app@sha256:a","sha256:a","sha256:a",None,None,"amd64","running","none","no",None,"p","app","/x",["/x/c.yml"])
        with patch("docker_update_manager.registry.remote_manifest") as remote:
            r=scan_service(s,tracking_image(s,None))
        self.assertEqual(r.status,"UNTRACKED DIGEST"); self.assertEqual(r.tracking_issue,"missing_channel"); self.assertIn("no trusted tracking tag",r.error); remote.assert_not_called()
        self.assertEqual(r.as_dict()["status"],"UNTRACKED DIGEST")
        self.assertEqual(r.as_dict()["tracking_issue"],"missing_channel")

if __name__=="__main__": unittest.main()


class ExplicitLocalBuildMarkerTests(unittest.TestCase):
    """io.upt.local-build is trusted only as a Compose container declaration."""

    def container(self, marker=None, compose=True):
        c=json.loads(json.dumps(C)); c["Name"]="/example-stack"; c["Config"]["Image"]="example-stack"
        labels={"com.docker.compose.project":"example-stack","com.docker.compose.service":"web",
                "com.docker.compose.project.working_dir":"/opt/example-stack",
                "com.docker.compose.project.config_files":"/opt/example-stack/compose.yml"} if compose else {}
        if marker is not None: labels["io.upt.local-build"]=marker
        c["Config"]["Labels"]=labels
        return c

    def image(self, labels=None):
        return {"Id":"i1","RepoTags":["example-stack:latest"],"RepoDigests":[],"Architecture":"amd64","Config":{"Labels":labels}}

    def discover_one(self, container, images):
        with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([container]), json.dumps(images)]):
            return discover()[0]

    def test_compose_declared_marker_is_local_build_without_registry_lookup(self):
        service=self.discover_one(self.container("true"), [self.image()])
        self.assertTrue(service.local_build)
        self.assertIsNone(service.digest)
        with patch("docker_update_manager.registry.remote_manifest") as remote:
            self.assertEqual(scan_service(service).status, "LOCAL BUILD")
            self.assertEqual(scan_service_with_tracking(service, State(tempfile.mkdtemp())).status, "LOCAL BUILD")
        remote.assert_not_called()

    def test_unmarked_name_without_repo_digests_is_not_local_build(self):
        service=self.discover_one(self.container(), [self.image()])
        self.assertFalse(service.local_build)
        with patch("docker_update_manager.registry.remote_manifest", side_effect=ValueError("unauthorized")) as remote:
            self.assertEqual(scan_service(service).status, "REGISTRY ERROR")
        remote.assert_called_once()
        found={"digest": "sha256:"+"b"*64, "platforms": [], "version": None, "created": None}
        with patch("docker_update_manager.registry.remote_manifest", return_value=found):
            self.assertEqual(scan_service(service).status, "UNKNOWN")

    def test_non_canonical_marker_values_are_not_local_build(self):
        for value in ("false", "", "1", "yes", "True", "TRUE", " true", "true ", "on", "true,false"):
            with self.subTest(value=value):
                self.assertFalse(self.discover_one(self.container(value), [self.image()]).local_build)

    def test_image_inherited_marker_is_untrusted(self):
        for labels in ({"io.upt.local-build": "true"}, {"io.upt.local-build": "false"}, {"io.upt.local-build": ""}):
            with self.subTest(labels=labels):
                # Container labels report the merged value, so presence of the
                # key on the image makes its origin unprovable.
                self.assertFalse(self.discover_one(self.container("true"), [self.image(labels)]).local_build)

    def test_marker_requires_inspectable_image_and_compose_service(self):
        self.assertFalse(self.discover_one(self.container("true"), []).local_build)
        self.assertFalse(self.discover_one(self.container("true", compose=False), [self.image()]).local_build)

    def test_marked_local_build_is_excluded_from_registry_update_paths(self):
        # A repository digest is present so only the local-build gate excludes it.
        image=dict(self.image(), RepoDigests=["example-stack@sha256:"+"a"*64])
        service=self.discover_one(self.container("true"), [image])
        self.assertTrue(service.local_build)
        self.assertEqual(service.digest, "sha256:"+"a"*64)
        with patch("docker_update_manager.registry.remote_manifest") as remote:
            accepted, results=actionable_updates([service], None)
        remote.assert_not_called()
        self.assertEqual(accepted, [])
        self.assertEqual(results[0].status, "LOCAL BUILD")


class LocalBuildCliRollbackTests(unittest.TestCase):
    """Explicit `upt rollback` honours current Local build classification."""

    def setUp(self):
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        self.root=Path(temp.name); self.compose=self.root/"compose.yml"; self.compose.write_text("services: {}\n")
        backup=self.root/"backup"; backup.mkdir(); (backup/"compose.yml").write_text("services: {}\n")
        (backup/"metadata.json").write_text(json.dumps({"files": [{"source": str(self.compose), "backup": str(backup/"compose.yml")}]}))
        self.state=State(self.root/"state")
        # History from when the service was registry-managed and UPT updated it.
        self.state.record(stack="example-stack", service="web", action="update", old_image="docker.io/library/nginx:1.0",
                          old_image_id="sha256:"+"0"*64, new_image="docker.io/library/nginx:1.1",
                          backup=str(backup), result="SUCCESS")

    def rollback(self, configured, marker=None, dry_run=False):
        labels={"com.docker.compose.project": "example-stack", "com.docker.compose.service": "web",
                "com.docker.compose.project.working_dir": str(self.root),
                "com.docker.compose.project.config_files": str(self.compose)}
        if marker is not None: labels["io.upt.local-build"]=marker
        container=json.loads(json.dumps(C)); container["Name"]="/example-stack-web-1"
        container["Config"].update(Image=configured, Labels=labels)
        image={"Id": "i1", "RepoDigests": ["docker.io/library/nginx@sha256:"+"a"*64], "Architecture": "amd64", "Config": {"Labels": {}}}
        argv=["rollback", "web"]+(["--dry-run"] if dry_run else ["-y"])
        p=parser(); args=p.parse_args(argv)
        self.mutation_safe=Mock(); self.docker=Mock(return_value=""); self.write=Mock()
        with patch("docker_update_manager.docker.run", side_effect=["c1\n", json.dumps([container]), json.dumps([image])]), \
             patch("docker_update_manager.registry.remote_manifest") as self.remote, \
             patch("docker_update_manager.operations.require_mutation_safe", self.mutation_safe), \
             patch("docker_update_manager.operations.run", self.docker), \
             patch("docker_update_manager.operations.atomic_write", self.write), \
             patch("docker_update_manager.operations.validate"), \
             patch("docker_update_manager.operations.discover", side_effect=RuntimeError("stop after recreate")), \
             contextlib.redirect_stdout(io.StringIO()):
            return execute(args, p, Config(path=str(self.root/"config.yml")), self.state, Reporter(enabled=False))

    def assert_refused_before_mutation(self, configured, marker=None):
        for dry_run in (False, True):
            with self.subTest(configured=configured, dry_run=dry_run):
                history=len(self.state.history())
                with self.assertRaisesRegex(PreMutationRefusal, "local build; registry rollback is not available"):
                    self.rollback(configured, marker, dry_run)
                self.mutation_safe.assert_not_called(); self.docker.assert_not_called(); self.write.assert_not_called()
                self.remote.assert_not_called()
                self.assertEqual(len(self.state.history()), history)
                self.assertEqual(self.compose.read_text(), "services: {}\n")

    def test_explicitly_marked_local_build_refuses_cli_rollback(self):
        self.assert_refused_before_mutation("example-stack", "true")

    def test_conventional_local_build_refuses_cli_rollback(self):
        self.assert_refused_before_mutation("example-stack-web")

    def test_registry_managed_service_keeps_existing_rollback_path(self):
        with self.assertRaisesRegex(RuntimeError, "stop after recreate"):
            self.rollback("docker.io/library/nginx:1.1")
        self.mutation_safe.assert_called()
        self.write.assert_called_once()
        commands=[call.args[0] for call in self.docker.call_args_list]
        self.assertIn(["docker", "image", "tag", "sha256:"+"0"*64, "docker.io/library/nginx:1.0"], commands)
        self.assertTrue(any(command[-4:]==["up", "-d", "--no-deps", "web"] for command in commands))
        self.remote.assert_not_called()

    def test_non_canonical_marker_does_not_block_registry_rollback(self):
        with self.assertRaisesRegex(RuntimeError, "stop after recreate"):
            self.rollback("docker.io/library/nginx:1.1", "yes")
        self.write.assert_called_once()
