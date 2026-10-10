"""Conservative, presentation-only release labels for web views.

Image tags can be useful identity when an image publishes no version metadata,
but a tag is never an update target or evidence that a registry result is
current. Keep this resolver separate from scan and mutation decisions.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import MUTABLE_TAGS, parse_image_ref


_RELEASE_TAG = re.compile(r"v?\d+(?:\.\d+){1,5}(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?", re.IGNORECASE)
_CHANNEL_SUFFIX = re.compile(
    r"(?:^|[-.])(?:latest|stable|main|master|develop|development|dev|beta|nightly|"
    r"edge|canary|rolling)(?:$|[-.])",
    re.IGNORECASE,
)
_CHANNEL_NAME = re.compile(
    r"(?<![A-Za-z0-9])(?:latest|stable|main|master|develop|development|dev|beta|nightly|"
    r"edge|canary|rolling)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_MUTABLE_SUFFIXES = tuple(f"-{tag}" for tag in MUTABLE_TAGS) + (
    "-nightly", "-development", "-canary", "-rolling", "-main", "-master",
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class DisplayVersion:
    value: str | None
    source: str | None


def is_release_like_tag(tag: object) -> bool:
    """Accept only bounded numeric-leading tags that look like release IDs."""
    if not isinstance(tag, str) or not tag or len(tag) > 64:
        return False
    value = tag.strip()
    if value != tag or not _RELEASE_TAG.fullmatch(value):
        return False
    lowered = value.lower()
    if lowered in MUTABLE_TAGS or lowered.endswith(_MUTABLE_SUFFIXES):
        return False
    return _CHANNEL_SUFFIX.search(lowered) is None


def display_version(metadata: object, image: object) -> DisplayVersion:
    """Prefer published version metadata, with a safe image-tag display fallback.

    ``source`` is ``metadata`` or ``tag`` so views can label provenance. The
    returned value is deliberately not stored on Service/ScanResult and must
    not be used to select, compare, or authorize an image mutation.
    """
    if isinstance(metadata, str):
        published = metadata.strip().strip('"').strip()
        concrete_release = len(published) <= 128 and _RELEASE_TAG.fullmatch(published)
        if published and published.lower() != "unknown" and (concrete_release or _CHANNEL_NAME.search(published) is None):
            return DisplayVersion(published, "metadata")
    if isinstance(image, str) and image:
        try:
            tag = parse_image_ref(image).tag
        except (AttributeError, TypeError, ValueError):
            tag = ""
        if is_release_like_tag(tag):
            return DisplayVersion(tag, "tag")
    return DisplayVersion(None, None)


def display_channel(image: object, trusted_tag: object = None) -> str | None:
    """Return a real configured/trusted tracking channel, without guessing pins."""
    if isinstance(trusted_tag, str) and 0 < len(trusted_tag) <= 128 and not any(
        character in trusted_tag for character in "\0\r\n/@"
    ):
        return None if is_release_like_tag(trusted_tag) else trusted_tag
    if not isinstance(image, str) or not image:
        return None
    try:
        ref = parse_image_ref(image)
    except (AttributeError, TypeError, ValueError):
        return None
    base = image.split("@", 1)[0]
    last = base.rsplit("/", 1)[-1]
    colon = last.rfind(":")
    explicit_tag = colon >= 0
    if explicit_tag and (ref.tag.lower() in MUTABLE_TAGS or ref.tag.lower().endswith(_MUTABLE_SUFFIXES)):
        return ref.tag
    if not explicit_tag and not ref.digest:
        return "latest"  # Docker's documented implicit tag for an unpinned reference.
    return None


def display_repository(image: object) -> str | None:
    """Return the registry/repository portion for compact identity labels."""
    if not isinstance(image, str) or not image:
        return None
    try:
        ref = parse_image_ref(image)
    except (AttributeError, TypeError, ValueError):
        return None
    return f"{ref.registry}/{ref.repository}"


def short_digest(value: object) -> str | None:
    """Shorten only a valid sha256 digest; the full value remains separately available."""
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        return None
    return f"{value[:15]}…{value[-5:]}"


def exact_digest_reference(image: object, digest: object) -> str | None:
    """Build a display-only immutable reference from server-provided facts."""
    if not isinstance(image, str) or not image or not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        return None
    base = image.split("@", 1)[0]
    slash = base.rfind("/")
    colon = base.rfind(":")
    if colon > slash:
        base = base[:colon]
    return f"{base}@{digest}"


def inventory_identity(item: dict) -> str:
    """Describe scan facts for the Services view; never select an update target."""
    service = item.get("service") or {}
    status = item.get("status")
    if item.get("runtime_only"):
        return "Not scanned"
    if status == "UNTRACKED DIGEST":
        return "Digest pinned · tracking unavailable"

    current = display_version(service.get("version"), service.get("image"))
    target = display_version(item.get("remote_version"), item.get("target_image"))
    trusted_tag = item.get("tracking_tag")
    channel = display_channel(service.get("image"), trusted_tag)
    pinned = bool(service.get("digest") and "@sha256:" in (service.get("image") or ""))
    # A trusted, version-like tracking tag is not a channel, but it is still
    # display-only identity for a digest pin. Keep it bounded and never treat it
    # as an update target: it is only rendered from the server-projected scan
    # fact and is cleared on runtime reconciliation.
    release_tag = trusted_tag if is_release_like_tag(trusted_tag) else None

    if status in {"UPDATE", "PINNED UPDATE"} and current.value and target.value:
        prefix = "Tag " if current.source == "tag" else ""
        return f"{prefix}{current.value} → {target.value}"
    if current.value:
        label = "Configured tag" if current.source == "tag" else "Published version"
        suffix = " · digest changed" if status == "DIGEST CHANGED" else ""
        return f"{label} {current.value}{suffix}"
    if channel:
        label = "Tracking channel" if pinned and item.get("tracking_tag") else ("Configured channel" if pinned else "Channel")
        if status == "DIGEST CHANGED":
            return f"Digest changed · {label.lower()} {channel}"
        if status in {"UPDATE", "PINNED UPDATE"}:
            if target.value:
                target_label = "target tag" if target.source == "tag" else "target version"
                return f"{label} {channel} → {target_label} {target.value}"
            return f"{label} {channel} · update available"
        return f"{label} {channel}"
    if release_tag:
        if status == "DIGEST CHANGED":
            return f"Digest changed · tracking tag {release_tag}"
        if status in {"UPDATE", "PINNED UPDATE"}:
            return f"Target tag {release_tag}"
        return f"Tracking tag {release_tag}"
    if target.value and status in {"UPDATE", "PINNED UPDATE"}:
        label = "target tag" if target.source == "tag" else "target published version"
        return f"Update available · {label} {target.value}"
    if status == "DIGEST CHANGED":
        return "Digest changed"
    if pinned:
        return "Digest pinned"
    return "Version not published"


_UPDATE_STATES = {"UPDATE", "DIGEST CHANGED", "PINNED UPDATE"}
_UNDETERMINED_REASONS = {
    "UNKNOWN": "The last scan could not determine whether a newer image exists.",
    "REGISTRY ERROR": "The registry could not be queried during the last scan.",
    "ARCH UNSUPPORTED": "The registry publishes no image for this host architecture.",
    "UNTRACKED DIGEST": "Digest-pinned without a recorded tracking channel; UPT does not guess one.",
    "CHECK REQUIRED": "Update information is stale or unverified. Check this service again.",
}
_RECONCILED_REASON = "The container changed since the inventory scan; check this service to verify its update information."
_SKIPPED_REASONS = {
    "LOCAL BUILD": "Built locally; there is no registry image to compare.",
    "IGNORED": "Excluded from update checks.",
}


def _fact(value, kind, label):
    return {"value": value, "kind": kind, "label": label}


def update_identity(item: dict) -> dict:
    """Structured, display-only current/available facts for update listings.

    Complements ``inventory_identity`` for tabular views. Every value comes
    from server-projected scan facts; a missing version is labelled as missing
    rather than shown as ``Unknown`` and nothing here selects an update target.
    """
    service = item.get("service") or {}
    status = str(item.get("status") or "UNKNOWN").upper()
    if item.get("runtime_only"):
        return {"state": "not_scanned", "current": _fact(None, "none", "Not scanned"),
                "available": None, "reason": "This service has not been checked for updates yet."}

    image = service.get("image")
    pinned = bool(service.get("digest") and "@sha256:" in (image or ""))
    current_release = display_version(service.get("version"), image)
    channel = None if status == "UNTRACKED DIGEST" else display_channel(image, item.get("tracking_tag"))
    trusted_tag = item.get("tracking_tag")
    digest = short_digest(service.get("digest"))
    if current_release.value:
        current = _fact(current_release.value, "tag" if current_release.source == "tag" else "version",
                        "Image tag" if current_release.source == "tag" else "Published version")
    elif channel:
        current = _fact(channel, "channel", "Tracking channel" if pinned and trusted_tag else "Channel")
    elif pinned and is_release_like_tag(trusted_tag):
        current = _fact(trusted_tag, "tag", "Tracking tag")
    elif digest:
        current = _fact(digest, "digest", "Pinned digest" if pinned else "Digest; no version label")
    else:
        current = _fact(None, "none", "No version published")

    available = None
    if status in _UPDATE_STATES:
        target = display_version(item.get("remote_version"), item.get("target_image"))
        remote_digest = short_digest(item.get("remote_digest"))
        if target.value and target.value != current.get("value"):
            available = _fact(target.value, "tag" if target.source == "tag" else "version",
                              "Image tag" if target.source == "tag" else "Published version")
        elif remote_digest:
            available = _fact(remote_digest, "digest", "New digest; no version label")
        else:
            available = _fact(None, "none", "New image available")
        state, reason = "update", None
    elif status == "CURRENT":
        state, reason = "current", None
    elif status == "PINNED":
        state, reason = "pinned", None
    elif status in _SKIPPED_REASONS:
        state, reason = "skipped", item.get("error") or _SKIPPED_REASONS[status]
    else:
        state = "undetermined"
        reason = item.get("error") or (_RECONCILED_REASON if status == "CHECK REQUIRED" and item.get("runtime_reconciled")
                                       else _UNDETERMINED_REASONS.get(status, _UNDETERMINED_REASONS["UNKNOWN"]))
    return {"state": state, "current": current, "available": available, "reason": reason}
