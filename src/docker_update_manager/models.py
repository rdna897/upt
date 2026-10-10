from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any

MUTABLE_TAGS = {"latest", "stable", "main", "master", "develop", "development", "dev", "beta", "nightly", "edge", "canary", "rolling"}

@dataclass
class ImageRef:
    original: str
    registry: str
    repository: str
    tag: str = "latest"
    digest: str | None = None

    @property
    def mutable(self) -> bool:
        return not self.digest and (self.tag.lower() in MUTABLE_TAGS or self.tag.lower().endswith(("-latest", "-stable", "-edge")))

    @property
    def pin_type(self) -> str:
        return "DIGEST PIN" if self.digest else ("MUTABLE" if self.mutable else "VERSION PIN")

def parse_image_ref(value: str) -> ImageRef:
    original = value
    digest = None
    if "@" in value:
        value, digest = value.rsplit("@", 1)
    slash = value.rfind("/")
    colon = value.rfind(":")
    tag = value[colon + 1:] if colon > slash else "latest"
    name = value[:colon] if colon > slash else value
    first, sep, rest = name.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        registry, repository = first, rest
    else:
        registry, repository = "docker.io", name
        if "/" not in repository:
            repository = "library/" + repository
    return ImageRef(original, registry, repository, tag, digest)

@dataclass
class Service:
    name: str
    container_id: str
    image: str
    image_id: str
    digest: str | None
    version: str | None
    created: str | None
    architecture: str | None
    state: str
    health: str
    restart_policy: str
    started_at: str | None
    stack: str | None = None
    compose_service: str | None = None
    working_dir: str | None = None
    compose_files: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)
    local_build: bool = False
    ignored: bool = False
    network_mode: str | None = None

    @property
    def key(self) -> str:
        return self.compose_service or self.name

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["key"] = self.key
        data["mutable"] = parse_image_ref(self.image).mutable
        return data

@dataclass
class ScanResult:
    service: Service
    status: str
    remote_digest: str | None = None
    remote_version: str | None = None
    remote_created: str | None = None
    error: str | None = None
    tracking_issue: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"service": self.service.as_dict(), "status": self.status, "remote_digest": self.remote_digest,
                "remote_version": self.remote_version, "remote_created": self.remote_created, "error": self.error,
                "tracking_issue": self.tracking_issue}
