from __future__ import annotations
import json, re
from dataclasses import dataclass
from .models import Service, parse_image_ref
from .system import run

LOCAL_BUILD_LABEL = "io.upt.local-build"

def declared_local_build(container_labels, image, stack, compose_service) -> bool:
    """Return whether a Compose service explicitly declared itself a local build.

    Container Config.Labels merge image labels with labels supplied at
    container creation, so the marker is trusted only when the exact running
    image is inspectable and does not carry the key itself. A registry image
    therefore cannot self-classify by publishing the label; only the Compose
    service definition (services.<name>.labels) can set it. Only the exact
    value "true" is accepted. Absence of RepoDigests is never evidence.
    """
    if not (stack and compose_service and isinstance(image, dict) and image.get("Id")):
        return False
    image_labels = (image.get("Config") or {}).get("Labels") or {}
    if not isinstance(image_labels, dict) or LOCAL_BUILD_LABEL in image_labels:
        return False
    return container_labels.get(LOCAL_BUILD_LABEL) == "true"

def discover(config=None, all_containers=False) -> list[Service]:
    ids = run(["docker", "ps", "-aq" if all_containers else "-q"]).split()
    if not ids: return []
    containers = json.loads(run(["docker", "inspect", *ids]))
    image_ids = sorted({c["Image"] for c in containers})
    images = {i["Id"]: i for i in json.loads(run(["docker", "image", "inspect", *image_ids]))}
    result = []
    for c in containers:
        labels = c.get("Config", {}).get("Labels") or {}
        im = images.get(c["Image"], {})
        ilabels = (im.get("Config") or {}).get("Labels") or {}
        version = _version(ilabels, labels)
        state = c.get("State", {})
        health = (state.get("Health") or {}).get("Status", "none")
        configured_image=c["Config"].get("Image", "")
        digest = local_image_provenance(im, c["Image"], configured_image).digest
        files = [x for x in labels.get("com.docker.compose.project.config_files", "").split(",") if x]
        stack=labels.get("com.docker.compose.project"); compose_service=labels.get("com.docker.compose.service")
        conventional_build=bool(stack and compose_service and configured_image.removesuffix(":latest") in {f"{stack}-{compose_service}",f"{stack}_{compose_service}"})
        local_build=conventional_build or declared_local_build(labels, im, stack, compose_service)
        svc = Service(name=c["Name"].lstrip("/"), container_id=c["Id"], image=configured_image,
            image_id=c["Image"], digest=digest, version=version, created=im.get("Created"),
            architecture=im.get("Architecture"), state=state.get("Status", "unknown"), health=health,
            restart_policy=(c.get("HostConfig",{}).get("RestartPolicy") or {}).get("Name", "no"),
            started_at=state.get("StartedAt"), network_mode=c.get("HostConfig", {}).get("NetworkMode"), stack=stack,
            compose_service=compose_service,
            working_dir=labels.get("com.docker.compose.project.working_dir"), compose_files=files,
            labels=labels, local_build=local_build)
        svc.ignored = bool(config and config.ignored(svc))
        result.append(svc)
    return sorted(result, key=lambda s: (s.stack or "~standalone", s.key))

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}")

# Media types of a pullable repository target. An image config type is never a
# repository digest, so it is excluded deliberately.
_REPOSITORY_TARGET_MEDIA_TYPES = frozenset({
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.docker.distribution.manifest.v2+json",
})


@dataclass(frozen=True)
class LocalImageProvenance:
    image_id: str
    digest: str | None
    source: str | None  # "repo_digests", "descriptor" or None when unproven


def local_image_provenance(image, image_id, configured_image) -> LocalImageProvenance:
    """Resolve at most one local repository digest for the exact running image.

    RepoDigests remains the preferred source, bound to the configured repository. When it is empty
    (for example an image left dangling after its tag moved), the containerd
    image store's target Descriptor is accepted only if Docker's own Identity
    metadata binds it to the configured repository and the descriptor is the
    exact inspected image. Anything else stays unproven; the image ID, a
    remote manifest or history is never substituted for the digest.
    """
    unproven = LocalImageProvenance(image_id, None, None)
    if not isinstance(image, dict) or image.get("Id") != image_id:
        return unproven
    try:
        configured = parse_image_ref(configured_image)
    except (TypeError, ValueError, AttributeError):
        return unproven
    repo_digests = image.get("RepoDigests")
    if repo_digests:
        # Same standard as the fallback: only entries for the configured
        # repository count, and contradictory local metadata never falls
        # through to the descriptor.
        if not isinstance(repo_digests, list):
            return unproven
        matching = set()
        for entry in repo_digests:
            if not isinstance(entry, str) or entry.count("@") != 1:
                return unproven
            name, digest = entry.split("@")
            if not name or not _SHA256.fullmatch(digest):
                return unproven
            try:
                candidate = parse_image_ref(name)
            except (TypeError, ValueError):
                return unproven
            if (candidate.registry, candidate.repository) == (configured.registry, configured.repository):
                matching.add(digest)
        if len(matching) != 1:
            return unproven
        digest = matching.pop()
        if configured.digest is not None and configured.digest != digest:
            return unproven
        return LocalImageProvenance(image_id, digest, "repo_digests")
    descriptor = image.get("Descriptor")
    if not isinstance(descriptor, dict):
        return unproven
    digest = descriptor.get("digest")
    # In the containerd store the image ID is the target descriptor digest;
    # disagreement means the metadata is not the documented shape.
    if (descriptor.get("mediaType") not in _REPOSITORY_TARGET_MEDIA_TYPES
            or not isinstance(digest, str) or not _SHA256.fullmatch(digest)
            or digest != image_id):
        return unproven
    identity = image.get("Identity")
    pulls = identity.get("Pull") if isinstance(identity, dict) else None
    if not isinstance(pulls, list) or not pulls:
        return unproven
    try:
        repositories = set()
        for pull in pulls:
            repository = pull.get("Repository") if isinstance(pull, dict) else None
            # Identity records a bare repository; a tag or digest is malformed.
            if (not isinstance(repository, str) or not repository or "@" in repository
                    or ":" in repository.rsplit("/", 1)[-1]):
                return unproven
            parsed = parse_image_ref(repository)
            repositories.add((parsed.registry, parsed.repository))
    except (TypeError, ValueError, AttributeError):
        return unproven
    if (configured.registry, configured.repository) not in repositories:
        return unproven
    if configured.digest is not None and configured.digest != digest:
        return unproven
    return LocalImageProvenance(image_id, digest, "descriptor")


def _version(*label_sets):
    for labels in label_sets:
        for key in ("org.opencontainers.image.version", "version", "build_version"):
            val = labels.get(key)
            if val and val.strip(' "') and val.lower() not in {"latest", "unknown"}:
                if key == "build_version" and "version:-" in val: val = val.split("version:-",1)[1].split(" Build-date",1)[0].strip()
                return val.strip(' "')
    return None

def compose_args(s: Service, *, project_name: str | None = None) -> list[str]:
    if not s.stack or not s.working_dir or not s.compose_files: raise ValueError(f"{s.key} is not a discoverable Compose service")
    args = ["docker", "compose", "--project-directory", s.working_dir]
    if project_name is not None:
        if project_name != s.stack: raise ValueError("Compose project identity changed")
        args += ["--project-name", project_name]
    for f in s.compose_files: args += ["-f", f]
    return args

def resolve_service(services, name):
    exact = [s for s in services if name in {s.key, s.name, f"{s.stack}/{s.key}"}]
    if len(exact) == 1: return exact[0]
    if len(exact) > 1: raise ValueError(f"ambiguous service '{name}'; use STACK/SERVICE")
    import difflib
    choices = sorted({s.key for s in services})
    hint = difflib.get_close_matches(name, choices, n=1)
    raise ValueError(f"Unknown service: {name}" + (f"\n\nDid you mean:\n  {hint[0]}" if hint else ""))
