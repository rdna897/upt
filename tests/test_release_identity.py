import _upt_isolation  # noqa: F401 - must stay first; see scripts/run_tests.py
import unittest

from docker_update_manager.release_identity import (
    display_channel,
    display_version,
    inventory_identity,
    exact_digest_reference,
    is_release_like_tag,
    short_digest,
)


class DisplayVersionTests(unittest.TestCase):
    def test_published_metadata_precedes_configured_release_tag(self):
        resolved = display_version("4.0.15", "ghcr.io/example/app:1.2.3")
        self.assertEqual((resolved.value, resolved.source), ("4.0.15", "metadata"))

    def test_explicit_numeric_release_tags_are_display_only_fallbacks(self):
        for tag in ("1.2.3", "v1.2.3", "4.0.15-ls123", "2026.09"):
            with self.subTest(tag=tag):
                resolved = display_version(None, f"ghcr.io/example/app:{tag}")
                self.assertEqual((resolved.value, resolved.source), (tag, "tag"))

    def test_mutable_channels_and_channel_suffixes_are_not_versions(self):
        for tag in (
            "latest", "stable", "main", "master", "develop", "development",
            "dev", "beta", "nightly", "edge", "canary", "rolling",
            "app-latest", "app-stable", "app-edge", "1.2.3-nightly",
            "1.2.3-dev", "1.2.3-beta",
        ):
            with self.subTest(tag=tag):
                self.assertFalse(is_release_like_tag(tag))
                self.assertIsNone(display_version(None, f"ghcr.io/example/app:{tag}").value)

    def test_published_channel_labels_are_not_misreported_as_versions(self):
        for metadata in ("latest", "stable", "nightly", "edge", "dev", "beta"):
            with self.subTest(metadata=metadata):
                resolved = display_version(metadata, f"ghcr.io/example/app:{metadata}")
                self.assertIsNone(resolved.value)

    def test_concrete_published_prereleases_remain_versions(self):
        for metadata in ("1.2.3-beta.1", "4.0.15-nightly", "v2.0.0-rc.1", "1.2.3-edge"):
            with self.subTest(metadata=metadata):
                resolved = display_version(metadata, "ghcr.io/example/app:latest")
                self.assertEqual((resolved.value, resolved.source), (metadata, "metadata"))
                if any(word in metadata for word in ("edge", "nightly", "beta")):
                    self.assertFalse(is_release_like_tag(metadata))

    def test_inventory_prefers_proven_identity_without_inventing_current_version(self):
        def item(version, image, status="CURRENT", remote_version=None, tracking_tag=None, target_image=None):
            return {"service": {"version": version, "image": image, "digest": "sha256:" + "a" * 64},
                    "status": status, "remote_version": remote_version, "tracking_tag": tracking_tag,
                    "target_image": target_image}
        pin = "example/app@sha256:" + "a" * 64
        target_pin = "example/app:1.2.4@sha256:" + "b" * 64
        cases = (
            (item("4.0.15", "example/app:latest", "UPDATE", "4.0.16"), "4.0.15 → 4.0.16"),
            (item(None, "example/app:1.2.3"), "Configured tag 1.2.3"),
            (item(None, "example/app:latest", "DIGEST CHANGED"), "Digest changed · channel latest"),
            (item(None, "example/app@sha256:" + "a" * 64, "PINNED UPDATE", tracking_tag="stable"), "Tracking channel stable · update available"),
            (item(None, "example/app@sha256:" + "a" * 64, "UNTRACKED DIGEST"), "Digest pinned · tracking unavailable"),
            (item(None, "example/app:latest", "UPDATE", "4.0.16"), "Channel latest → target version 4.0.16"),
            (item(None, "example/app", "UPDATE", "4.0.16"), "Channel latest → target version 4.0.16"),
            # Finding 6: a trusted, version-like tracking tag is preserved as a
            # display-only target identity instead of falling back to a generic pin.
            (item(None, pin, "PINNED UPDATE", tracking_tag="1.2.4", target_image=target_pin), "Target tag 1.2.4"),
            (item(None, pin, "PINNED", tracking_tag="1.2.4"), "Tracking tag 1.2.4"),
        )
        for value, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(inventory_identity(value), expected)

    def test_version_like_tracking_tag_is_not_a_channel_and_untracked_pins_infer_nothing(self):
        pin = "example/app@sha256:" + "a" * 64
        # display_channel refuses to call a version-like tag a channel.
        self.assertIsNone(display_channel(pin, "1.2.4"))
        # An untracked pin neither infers a channel nor a release/target tag, even
        # when a status badge claims an update is pinned.
        untracked = {"service": {"version": None, "image": pin, "digest": "sha256:" + "a" * 64},
                     "status": "PINNED UPDATE", "remote_version": None, "tracking_tag": None,
                     "target_image": None}
        self.assertIsNone(display_channel(pin, untracked["tracking_tag"]))
        self.assertEqual(inventory_identity(untracked), "Digest pinned")

    def test_digest_pinned_mutable_channel_has_no_fabricated_version(self):
        image = "ghcr.io/example/app:latest@sha256:" + "a" * 64
        resolved = display_version(None, image)
        self.assertIsNone(resolved.value)
        self.assertIsNone(resolved.source)
        self.assertEqual(display_channel(image), "latest")

    def test_digest_only_pin_uses_only_a_trusted_history_channel(self):
        image = "ghcr.io/example/app@sha256:" + "a" * 64
        self.assertIsNone(display_channel(image))
        self.assertEqual(display_channel(image, "stable"), "stable")
        self.assertIsNone(display_channel(image, "1.2.3"))

    def test_exact_review_reference_and_short_form_keep_distinct_digest_tails(self):
        current = "sha256:" + "a" * 63 + "1"
        target = "sha256:" + "a" * 63 + "2"
        image = "ghcr.io/example/app:latest@" + current
        self.assertEqual(exact_digest_reference(image, target), "ghcr.io/example/app@" + target)
        self.assertNotEqual(short_digest(current), short_digest(target))
        self.assertEqual(short_digest(target), "sha256:" + "a" * 8 + "…" + "a" * 4 + "2")

    def test_tag_parser_is_bounded_and_requires_numeric_release_shape(self):
        self.assertFalse(is_release_like_tag("1.2.3-" + "a" * 70))
        self.assertTrue(is_release_like_tag("1.2"))
        for tag in ("release-1.2.3", "latest-1.2.3", "nightly"):
            with self.subTest(tag=tag):
                self.assertFalse(is_release_like_tag(tag))


if __name__ == "__main__":
    unittest.main()
