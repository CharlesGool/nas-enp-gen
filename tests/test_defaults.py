#!/usr/bin/env python3
"""
Regression test for the v0.1.3 default-mount-options fix (see
DECISIONS.md 2026-08-17 "Default CIFS mount options").

The Linux kernel's cifs.ko silently applies `soft` and `actimeo=1` when a
mount doesn't say otherwise (see `man mount.cifs`). Under heavy `git`
metadata churn on a soft-mounted share, that combination produced a real,
reproduced incident: a `rename()` on `.git/index` returned EACCES
permanently instead of the kernel retrying, wedging the file until the
mount was refreshed. The fix makes the generator's suggested CIFS default
explicit about `hard`/`actimeo=30` instead of relying on the kernel's
footgun defaults. This test guards against that suggestion silently
regressing back to the old string, and against the CLI and GUI defaults
drifting apart from each other.

Run: python3 tests/test_defaults.py    (stdlib unittest, no pytest needed)
"""
import importlib.util
import os
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_PATH = os.path.join(REPO_ROOT, "nas-enp-gen.py")

_spec = importlib.util.spec_from_file_location("nas_enp_gen", GEN_PATH)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


class TestDefaultCifsMountOptions(unittest.TestCase):
    def test_default_cifs_options_set_hard_and_actimeo(self):
        opts = gen.DEFAULT_CIFS_OPTIONS.split(",")
        self.assertIn("hard", opts,
            "default CIFS options must set 'hard' explicitly - leaving it "
            "unset lets the kernel silently fall back to 'soft', which "
            "caused the 2026-08-17 rename() EACCES lockup under git churn")
        self.assertTrue(
            any(o.startswith("actimeo=") and o != "actimeo=1" for o in opts),
            "default CIFS options must set actimeo to something longer "
            "than the kernel's 1-second default")

    def test_gui_and_cli_share_the_same_constant(self):
        # The GUI's _on_protocol_changed reads DEFAULT_CIFS_OPTIONS /
        # DEFAULT_NFS_OPTIONS directly (see nas-enp-gen.py), so there is
        # only one string to regress - this test documents that intent
        # and fails loudly if the module-level constants ever disappear.
        self.assertTrue(hasattr(gen, "DEFAULT_CIFS_OPTIONS"))
        self.assertTrue(hasattr(gen, "DEFAULT_NFS_OPTIONS"))
        self.assertIn("vers=3.0", gen.DEFAULT_CIFS_OPTIONS)


if __name__ == "__main__":
    unittest.main()
