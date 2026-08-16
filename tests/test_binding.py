#!/usr/bin/env python3
"""
Tests for the v0.1.0 machine-binding feature (see DESIGN.md "Envelope
format", DECISIONS.md 2026-08-16 entries, and the implementation guide's
section 8 test requirements).

Run: python3 tests/test_binding.py    (stdlib unittest, no pytest needed)

These tests build real client scripts with the real generator and run them
as real subprocesses with --selftest. The one test-only hook (a fake
fingerprint injected via a monkeypatched _fp_read) exists ONLY inside this
test file's own process; it is never written into a generated client
script, per guide section 8 item 1.
"""
import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GEN_PATH = os.path.join(REPO_ROOT, "nas-enp-gen.py")

_spec = importlib.util.spec_from_file_location("nas_enp_gen", GEN_PATH)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def base_cfg(**overrides):
    cfg = {
        "protocol": "cifs", "host": "203.0.113.42", "username": "test-user",
        "password": "test-password", "domain": "", "default_options": "vers=3.0",
        "mounts": [{"remote": "share", "local": "/mnt/test", "options": ""}],
        "retry_attempts": 1, "retry_delay_sec": 1, "install_deps": False,
    }
    cfg.update(overrides)
    return cfg


def this_machine_fingerprint():
    """Collect the real fingerprint of the machine running the tests, using
    the exact same client-embedded logic a generated script would use."""
    ns = _exec_client_namespace()
    return ns["collect_fingerprint"]()[0]


def _exec_client_namespace():
    """Decode+splice the client template and exec it in an isolated
    namespace (CONFIG_MODE doesn't matter, we only call helper functions,
    never load_config()). Used to reach collect_fingerprint()/
    fingerprint_selector() the same way a real generated client would."""
    src = (gen.py_client_template()
           .replace("__CONFIG_MODE__", "legacy")
           .replace("__CIPHERTEXT__", "").replace("__NONCE__", "")
           .replace("__KEYA__", "").replace("__KEYPAD__", "").replace("__ENVELOPE__", ""))
    ns = {"__name__": "nas_enp_mount_test", "__file__": "generated_client_under_test.py"}
    exec(compile(src, "generated_client_under_test.py", "exec"), ns)
    return ns


def run_selftest(path):
    r = subprocess.run([sys.executable, path, "--selftest"], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr


class TestBindingCryptoRoundTrip(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="nas-enp-gen-test-")
        self.this_fp = this_machine_fingerprint()

    def _write_client(self, cfg, name):
        src = gen.fill_template(cfg)
        path = os.path.join(self.tmpdir, name)
        with open(path, "w", newline="\n") as f:
            f.write(src)
        os.chmod(path, 0o700)
        gen.self_check_no_leak(src, cfg, path)  # must not raise
        return path

    def test_legacy_mode_unchanged(self):
        cfg = base_cfg(binding={"mode": "none", "fingerprints": []})
        path = self._write_client(cfg, "legacy.py")
        code, out, err = run_selftest(path)
        self.assertEqual(code, 0, err)
        self.assertIn("config decrypted OK", out)

    def test_cross_machine_failure(self):
        decoy = "a" * 64
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": [decoy]})
        path = self._write_client(cfg, "wrong_machine.py")
        code, out, err = run_selftest(path)
        self.assertNotEqual(code, 0)
        self.assertIn("slot match: NOT FOUND", out)
        self.assertIn("fingerprint mismatch", err)

    def test_matching_machine_succeeds(self):
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": [self.this_fp]})
        path = self._write_client(cfg, "right_machine.py")
        code, out, err = run_selftest(path)
        self.assertEqual(code, 0, err)
        self.assertIn("slot match: FOUND", out)
        self.assertIn("config decrypted OK", out)

    def test_multi_slot_3_of_4(self):
        b, c, d = "b" * 64, "c" * 64, "d" * 64
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": [self.this_fp, b, c]})
        path_in = self._write_client(cfg, "multi_in.py")
        code, out, _ = run_selftest(path_in)
        self.assertEqual(code, 0)

        cfg2 = base_cfg(binding={"mode": "machine", "fingerprints": [b, c, d]})
        path_out = self._write_client(cfg2, "multi_out.py")
        code2, out2, _ = run_selftest(path_out)
        self.assertNotEqual(code2, 0)
        self.assertIn("slot match: NOT FOUND", out2)

    def test_tamper_detection_no_plaintext_leak(self):
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": [self.this_fp]})
        path = self._write_client(cfg, "tamper.py")
        with open(path) as f:
            src = f.read()

        # locate BLOB_ENVELOPE = "<b64>" and corrupt one byte of the decoded JSON
        marker = 'BLOB_ENVELOPE = "'
        start = src.index(marker) + len(marker)
        end = src.index('"', start)
        env_b64 = src[start:end]
        envelope = json.loads(base64.b64decode(env_b64))
        ct = bytearray(base64.b64decode(envelope["payload"]["ct"]))
        ct[0] ^= 0xFF
        envelope["payload"]["ct"] = base64.b64encode(bytes(ct)).decode()
        new_env_b64 = base64.b64encode(json.dumps(envelope).encode()).decode()
        tampered_src = src[:start] + new_env_b64 + src[end:]
        tpath = os.path.join(self.tmpdir, "tampered.py")
        with open(tpath, "w") as f:
            f.write(tampered_src)

        code, out, err = run_selftest(tpath)
        self.assertNotEqual(code, 0)
        self.assertIn("fingerprint mismatch", err)  # GCM failure surfaces as mismatch, not a crash
        self.assertNotIn("test-password", out + err)

    def test_no_plaintext_leak_in_output(self):
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": [self.this_fp]})
        path = self._write_client(cfg, "leakcheck.py")
        with open(path) as f:
            src = f.read()
        for needle in (cfg["host"], cfg["username"], cfg["password"],
                       base64.b64encode(cfg["password"].encode()).decode()):
            self.assertNotIn(needle, src)

    def test_entropy_gate_rejects_placeholder_product_uuid(self):
        ns = _exec_client_namespace()
        real_fp_read = ns["_fp_read"]

        def fake_fp_read(path):
            # Test-only hook: lives entirely in this test process, never
            # written into any generated script (guide section 8 item 1).
            if path.endswith("product_uuid"):
                return "00000000-0000-0000-0000-000000000000"
            return real_fp_read(path)

        ns["_fp_read"] = fake_fp_read
        with self.assertRaises(SystemExit) as ctx:
            ns["collect_fingerprint"]()
        self.assertIn("product_uuid unavailable or placeholder", str(ctx.exception))

    def test_kdf_timing_within_boot_budget(self):
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": [self.this_fp]})
        path = self._write_client(cfg, "timing.py")
        start = time.monotonic()
        code, out, err = run_selftest(path)
        elapsed = time.monotonic() - start
        self.assertEqual(code, 0, err)
        # generous bound: real n=2**15 Scrypt is ~0.1s; TimeoutStartSec=150
        self.assertLess(elapsed, 10.0, f"selftest took {elapsed:.2f}s, investigate before trusting boot budget")


class TestBindingValidation(unittest.TestCase):
    def test_missing_binding_rejected(self):
        cfg = base_cfg()
        with self.assertRaises(SystemExit):
            gen.validate(cfg)

    def test_bad_mode_rejected(self):
        cfg = base_cfg(binding={"mode": "wat"})
        with self.assertRaises(SystemExit):
            gen.validate(cfg)

    def test_machine_mode_requires_fingerprints(self):
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": []})
        with self.assertRaises(SystemExit):
            gen.validate(cfg)

    def test_invalid_fingerprint_hex_rejected(self):
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": ["not-hex"]})
        with self.assertRaises(SystemExit):
            gen.validate(cfg)

    def test_duplicate_fingerprints_deduped(self):
        fp = "e" * 64
        cfg = base_cfg(binding={"mode": "machine", "fingerprints": [fp, fp.upper()]})
        gen.validate(cfg)
        self.assertEqual(cfg["binding"]["fingerprints"], [fp])

    def test_none_mode_needs_no_fingerprints(self):
        cfg = base_cfg(binding={"mode": "none"})
        gen.validate(cfg)  # must not raise


if __name__ == "__main__":
    unittest.main()
