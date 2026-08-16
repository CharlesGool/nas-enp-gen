#!/usr/bin/env python3
"""
nas-enp-mount generator (server side)
Collects NAS connection details + mount mappings, encrypts them
(AES-256-GCM), and fills them into a plain Python client script.

The generated script decrypts the config only in memory at run time; the
plaintext IP / account / password never sit on the client's disk as a
separate file, and grepping the script only reveals base64 ciphertext.

SECURITY REALITY CHECK
----------------------
This is obfuscation, not unbreakable secrecy. A client that can mount the
share must be able to produce the credentials, so anyone with root on that
client can still recover them (RAM dump, strace, packet capture). Treat the
script as "raises the bar a bit", and pair it with a DEDICATED, LEAST-
PRIVILEGE, REVOCABLE NAS account so a leak is small and you can kill it by
changing one password on the NAS.

Requirements on this machine:
  - Python 3.8+  with the `cryptography` package  (pip install cryptography)
  - PySide6, for the GUI (auto-installed via pip on first GUI launch;
    not needed for --config/--cli headless use)

Requirements on each client machine (Debian/Ubuntu Linux, root):
  - Python 3.8+  with the `cryptography` package (auto-installed via pip
    by the client script itself on first run if missing)

MACHINE BINDING
---------------
binding.mode = "machine" derives the client's decryption key from each
target machine's hardware fingerprint (see DESIGN.md "Envelope format")
instead of embedding a recoverable key. A file leaked off its bound
machine(s) is computationally useless. This does NOT protect against an
attacker with root on a bound machine — see the security reality check
above, which still applies in full on that machine.
Collect fingerprints on each target first:  nas-enp-gen.py --emit-collector

Usage:
  python3 nas-enp-gen.py                       # launch the GUI
  python3 nas-enp-gen.py --cli                  # interactive terminal prompts
  python3 nas-enp-gen.py --config nas.json      # from a JSON file, headless
  python3 nas-enp-gen.py --config nas.json --out nas-enp-mount.py
  python3 nas-enp-gen.py --emit-collector       # write a fingerprint collector
"""
import argparse, base64, getpass, hashlib, json, os, random, re, subprocess, sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
except ImportError:
    sys.exit("Missing dependency. Run:  pip install cryptography")

# ---- Shared fingerprint-collection logic ----
# The ONE canonical copy. Spliced verbatim into both the client template
# (replacing the "# __FINGERPRINT_LOGIC__" marker below) and the
# --emit-collector output, so the two places that read hardware
# identifiers can never drift apart. See DECISIONS.md 2026-08-16
# "Machine-fingerprint key derivation".
FINGERPRINT_LOGIC_SRC = '''\
_FP_PLACEHOLDERS = {
    "", "none", "0", "default string", "to be filled by o.e.m.",
    "not specified", "not applicable", "system serial number",
    "unknown", "invalid", "00000000-0000-0000-0000-000000000000",
}


def _fp_read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def _fp_valid(v):
    return v is not None and v.strip().lower() not in _FP_PLACEHOLDERS


def _fp_root_disk_serial():
    try:
        root_dev = None
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[1] == "/":
                    root_dev = parts[0]
                    break
        if not root_dev or not root_dev.startswith("/dev/"):
            return None
        name = os.path.basename(os.path.realpath(root_dev))
        if re.match(r"^nvme\\d+n\\d+p\\d+$", name):
            base = re.sub(r"p\\d+$", "", name)
        else:
            base = re.sub(r"\\d+$", "", name)
        return _fp_read(f"/sys/block/{base}/device/serial")
    except Exception:
        return None


def collect_fingerprint():
    """Collect this machine's hardware fingerprint.
    Returns (fingerprint_hex, used[list[str]], skipped[list[str]]).
    Raises SystemExit if product_uuid is unavailable or a placeholder —
    this machine cannot be securely bound, and there is no lower-entropy
    fallback (see DESIGN.md 'Envelope format', entropy gate)."""
    if os.geteuid() != 0:
        raise SystemExit("FATAL: fingerprint collection requires root (product_uuid is root-only).")

    used = {}
    skipped = []

    product_uuid = _fp_read("/sys/class/dmi/id/product_uuid")
    if _fp_valid(product_uuid):
        used["product_uuid"] = product_uuid.strip().lower()
    else:
        skipped.append("product_uuid" + (" (placeholder)" if product_uuid else " (missing)"))

    if "product_uuid" not in used:
        raise SystemExit(
            "FATAL: product_uuid unavailable or placeholder.\\n"
            "This machine cannot be securely bound. Options:\\n"
            "  - run as root (product_uuid is root-only)\\n"
            "  - if this is a VM, ensure the hypervisor exposes a unique SMBIOS UUID\\n"
            "  - fall back to binding.mode = \\"none\\" (NO leak protection, see DESIGN.md)"
        )

    board_serial = _fp_read("/sys/class/dmi/id/board_serial")
    if _fp_valid(board_serial):
        used["board_serial"] = board_serial.strip().lower()
    else:
        skipped.append("board_serial" + (" (placeholder)" if board_serial else " (missing)"))

    product_serial = _fp_read("/sys/class/dmi/id/product_serial")
    if _fp_valid(product_serial):
        used["product_serial"] = product_serial.strip().lower()
    else:
        skipped.append("product_serial" + (" (placeholder)" if product_serial else " (missing)"))

    disk_serial = _fp_root_disk_serial()
    if _fp_valid(disk_serial):
        used["disk_serial"] = disk_serial.strip().lower()
    else:
        skipped.append("disk_serial" + (" (placeholder)" if disk_serial else " (missing)"))

    material = "\\n".join(f"{k}={used[k]}" for k in sorted(used))
    fingerprint = hashlib.sha256(material.encode()).hexdigest()
    return fingerprint, sorted(used), skipped


def fingerprint_selector(fingerprint):
    return hashlib.sha256((fingerprint + "nas-enp/selector/v2").encode()).digest()[:8].hex()
'''

# ---- Embedded Python client template (base64) ----
PY_CLIENT_TEMPLATE_B64 = (
    "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiIKbmFzLWVucC1tb3VudCBjbGllbnQKQnVpbHQgZnJvbSBhbiBlbmNyeXB0ZWQg"
    "Y29uZmlnIGJsb2IgZW1iZWRkZWQgYXQgZ2VuZXJhdGlvbiB0aW1lLgpUaGUgcGxhaW50ZXh0IGNvbmZpZyBuZXZlciB0b3Vj"
    "aGVzIGRpc2sgb24gdGhlIGNsaWVudC4KIiIiCmltcG9ydCBiYXNlNjQKaW1wb3J0IGhhc2hsaWIKaW1wb3J0IGpzb24KaW1w"
    "b3J0IG9zCmltcG9ydCByZQppbXBvcnQgc3VicHJvY2VzcwppbXBvcnQgc3lzCmltcG9ydCB0aW1lCmZyb20gc2h1dGlsIGlt"
    "cG9ydCB3aGljaAoKSU5TVEFMTF9ESVIgPSAiL3Jvb3QvbmFzLWVucC1tb3VudCIKQklOX05BTUUgPSAibmFzLWVucC1tb3Vu"
    "dC5weSIKU0VSVklDRV9OQU1FID0gIm5hcy1lbnAtbW91bnQuc2VydmljZSIKCiMgLS0tLSBFbWJlZGRlZCBibG9iIChmaWxs"
    "ZWQgaW4gYnkgdGhlIGdlbmVyYXRvcikgLS0tLQojIENPTkZJR19NT0RFIHNlbGVjdHMgd2hpY2ggZGVjcnlwdGlvbiBwYXRo"
    "IGxvYWRfY29uZmlnKCkgdGFrZXM7IGJvdGgKIyBwYXRocycgY29kZSBzdGF5cyBpbiBldmVyeSBnZW5lcmF0ZWQgc2NyaXB0"
    "LCBvbmx5IHRoZSBtb2RlIGRpZmZlcnMuCkNPTkZJR19NT0RFID0gIl9fQ09ORklHX01PREVfXyIgICMgImxlZ2FjeSIgb3Ig"
    "ImVudmVsb3BlIgpCTE9CX0NJUEhFUiA9ICJfX0NJUEhFUlRFWFRfXyIKQkxPQl9OT05DRSA9ICJfX05PTkNFX18iCkJMT0Jf"
    "S0VZQSA9ICJfX0tFWUFfXyIKQkxPQl9LRVlQQUQgPSAiX19LRVlQQURfXyIKQkxPQl9FTlZFTE9QRSA9ICJfX0VOVkVMT1BF"
    "X18iCgpGSU5HRVJQUklOVF9NSVNNQVRDSF9NU0cgPSAoCiAgICAiZmluZ2VycHJpbnQgbWlzbWF0Y2g6IHRoaXMgY2xpZW50"
    "IHdhcyBub3QgZ2VuZXJhdGVkIGZvciB0aGlzIG1hY2hpbmVcbiIKICAgICIob3IgdGhlIGhhcmR3YXJlIGNoYW5nZWQpLiBS"
    "ZWdlbmVyYXRlIGl0IHdpdGggbmFzLWVucC1nZW4gdXNpbmcgdGhpc1xuIgogICAgIm1hY2hpbmUncyBjdXJyZW50IGZpbmdl"
    "cnByaW50LiBSdW4gLS1zZWxmdGVzdCBmb3IgZGV0YWlscy4iCikKCgpkZWYgbG9nZihtc2cpOgogICAgcHJpbnQoZiJbbmFz"
    "LWVucC1tb3VudF0ge21zZ30iLCBmaWxlPXN5cy5zdGRlcnIpCgoKZGVmIF9waXBfaW5zdGFsbChwa2cpOgogICAgciA9IHN1"
    "YnByb2Nlc3MucnVuKFtzeXMuZXhlY3V0YWJsZSwgIi1tIiwgInBpcCIsICJpbnN0YWxsIiwgIi0tcXVpZXQiLCBwa2ddLAog"
    "ICAgICAgICAgICAgICAgICAgICAgICBjYXB0dXJlX291dHB1dD1UcnVlLCB0ZXh0PVRydWUpCiAgICBpZiByLnJldHVybmNv"
    "ZGUgIT0gMDoKICAgICAgICAjIHBpcCBtb2R1bGUgbWF5IGJlIG1pc3NpbmcgZW50aXJlbHkgb24gYSBtaW5pbWFsIGltYWdl"
    "OyBib290c3RyYXAgaXQgb25jZS4KICAgICAgICBzdWJwcm9jZXNzLnJ1bihbc3lzLmV4ZWN1dGFibGUsICItbSIsICJlbnN1"
    "cmVwaXAiLCAiLS1kZWZhdWx0LXBpcCJdLAogICAgICAgICAgICAgICAgICAgICAgICBjYXB0dXJlX291dHB1dD1UcnVlLCB0"
    "ZXh0PVRydWUpCiAgICAgICAgciA9IHN1YnByb2Nlc3MucnVuKFtzeXMuZXhlY3V0YWJsZSwgIi1tIiwgInBpcCIsICJpbnN0"
    "YWxsIiwgIi0tcXVpZXQiLCBwa2ddLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgY2FwdHVyZV9vdXRwdXQ9VHJ1ZSwg"
    "dGV4dD1UcnVlKQogICAgcmV0dXJuIHIKCgpkZWYgZW5zdXJlX2NyeXB0bygpOgogICAgdHJ5OgogICAgICAgIGZyb20gY3J5"
    "cHRvZ3JhcGh5Lmhhem1hdC5wcmltaXRpdmVzLmNpcGhlcnMuYWVhZCBpbXBvcnQgQUVTR0NNCiAgICAgICAgZnJvbSBjcnlw"
    "dG9ncmFwaHkuaGF6bWF0LnByaW1pdGl2ZXMua2RmLnNjcnlwdCBpbXBvcnQgU2NyeXB0CiAgICAgICAgcmV0dXJuIEFFU0dD"
    "TSwgU2NyeXB0CiAgICBleGNlcHQgSW1wb3J0RXJyb3I6CiAgICAgICAgbG9nZigiY3J5cHRvZ3JhcGh5IHBhY2thZ2UgbWlz"
    "c2luZzsgaW5zdGFsbGluZyB2aWEgcGlwIC4uLiIpCiAgICAgICAgciA9IF9waXBfaW5zdGFsbCgiY3J5cHRvZ3JhcGh5IikK"
    "ICAgICAgICBpZiByLnJldHVybmNvZGUgIT0gMDoKICAgICAgICAgICAgbG9nZihmImZhdGFsOiBwaXAgaW5zdGFsbCBjcnlw"
    "dG9ncmFwaHkgZmFpbGVkOlxue3Iuc3Rkb3V0fXtyLnN0ZGVycn0iKQogICAgICAgICAgICBzeXMuZXhpdCgyKQogICAgICAg"
    "IHRyeToKICAgICAgICAgICAgZnJvbSBjcnlwdG9ncmFwaHkuaGF6bWF0LnByaW1pdGl2ZXMuY2lwaGVycy5hZWFkIGltcG9y"
    "dCBBRVNHQ00KICAgICAgICAgICAgZnJvbSBjcnlwdG9ncmFwaHkuaGF6bWF0LnByaW1pdGl2ZXMua2RmLnNjcnlwdCBpbXBv"
    "cnQgU2NyeXB0CiAgICAgICAgICAgIHJldHVybiBBRVNHQ00sIFNjcnlwdAogICAgICAgIGV4Y2VwdCBJbXBvcnRFcnJvcjoK"
    "ICAgICAgICAgICAgbG9nZigiZmF0YWw6IGNyeXB0b2dyYXBoeSBzdGlsbCBub3QgaW1wb3J0YWJsZSBhZnRlciBpbnN0YWxs"
    "IikKICAgICAgICAgICAgc3lzLmV4aXQoMikKCgpBRVNHQ00sIFNjcnlwdCA9IGVuc3VyZV9jcnlwdG8oKQoKCmRlZiBkZWNv"
    "ZGVfYjY0KHMpOgogICAgdHJ5OgogICAgICAgIHJldHVybiBiYXNlNjQuYjY0ZGVjb2RlKHMpCiAgICBleGNlcHQgRXhjZXB0"
    "aW9uIGFzIGU6CiAgICAgICAgbG9nZihmImZhdGFsOiBibG9iIGRlY29kZSBlcnJvcjoge2V9IikKICAgICAgICBzeXMuZXhp"
    "dCgyKQoKCiMgX19GSU5HRVJQUklOVF9MT0dJQ19fCgoKZGVmIGxvYWRfY29uZmlnX2xlZ2FjeSgpOgogICAga2V5X2EgPSBk"
    "ZWNvZGVfYjY0KEJMT0JfS0VZQSkKICAgIGtleV9wYWQgPSBkZWNvZGVfYjY0KEJMT0JfS0VZUEFEKQogICAgaWYgbGVuKGtl"
    "eV9hKSAhPSBsZW4oa2V5X3BhZCk6CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKCJrZXkgbWF0ZXJpYWwgbGVuZ3RoIG1p"
    "c21hdGNoIikKICAgIGtleSA9IGJ5dGVhcnJheShhIF4gYiBmb3IgYSwgYiBpbiB6aXAoa2V5X2EsIGtleV9wYWQpKQogICAg"
    "dHJ5OgogICAgICAgIHBsYWluID0gQUVTR0NNKGJ5dGVzKGtleSkpLmRlY3J5cHQoZGVjb2RlX2I2NChCTE9CX05PTkNFKSwg"
    "ZGVjb2RlX2I2NChCTE9CX0NJUEhFUiksIE5vbmUpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgcmFpc2Ug"
    "UnVudGltZUVycm9yKGYiY29uZmlnIGF1dGgvZGVjcnlwdCBmYWlsZWQ6IHtlfSIpCiAgICBmaW5hbGx5OgogICAgICAgICMg"
    "YmVzdC1lZmZvcnQgemVyb2luZyBvZiB0aGUgbXV0YWJsZSBjb3B5OyB0aGUgYnl0ZXMoKSBjb3B5IHBhc3NlZCB0bwogICAg"
    "ICAgICMgQUVTR0NNIGFib3ZlIGlzIGltbXV0YWJsZSBhbmQgY2FuJ3QgYmUgemVyb2VkIHRoZSBzYW1lIHdheQogICAgICAg"
    "IGZvciBpIGluIHJhbmdlKGxlbihrZXkpKToKICAgICAgICAgICAga2V5W2ldID0gMAogICAgcmV0dXJuIGpzb24ubG9hZHMo"
    "cGxhaW4pCgoKZGVmIGxvYWRfY29uZmlnX2VudmVsb3BlKCk6CiAgICBlbnZlbG9wZSA9IGpzb24ubG9hZHMoZGVjb2RlX2I2"
    "NChCTE9CX0VOVkVMT1BFKSkKICAgIGZpbmdlcnByaW50LCB1c2VkLCBza2lwcGVkID0gY29sbGVjdF9maW5nZXJwcmludCgp"
    "CiAgICBzZWxlY3RvciA9IGZpbmdlcnByaW50X3NlbGVjdG9yKGZpbmdlcnByaW50KQogICAgc2xvdCA9IE5vbmUKICAgIGZv"
    "ciBzIGluIGVudmVsb3BlWyJzbG90cyJdOgogICAgICAgIGlmIHNbInNlbGVjdG9yIl0gPT0gc2VsZWN0b3I6CiAgICAgICAg"
    "ICAgIHNsb3QgPSBzCiAgICAgICAgICAgIGJyZWFrCiAgICBpZiBzbG90IGlzIE5vbmU6CiAgICAgICAgcmFpc2UgUnVudGlt"
    "ZUVycm9yKEZJTkdFUlBSSU5UX01JU01BVENIX01TRykKCiAgICBrZGYgPSBlbnZlbG9wZVsia2RmIl0KICAgIHNhbHQgPSBk"
    "ZWNvZGVfYjY0KHNsb3RbInNhbHQiXSkKICAgIGtlayA9IFNjcnlwdChzYWx0PXNhbHQsIGxlbmd0aD1rZGZbImRrbGVuIl0s"
    "IG49a2RmWyJuIl0sIHI9a2RmWyJyIl0sIHA9a2RmWyJwIl0pLmRlcml2ZShmaW5nZXJwcmludC5lbmNvZGUoKSkKICAgIHRy"
    "eToKICAgICAgICBkZWsgPSBBRVNHQ00oa2VrKS5kZWNyeXB0KGRlY29kZV9iNjQoc2xvdFsibm9uY2UiXSksIGRlY29kZV9i"
    "NjQoc2xvdFsid3JhcHBlZF9kZWsiXSksIGIibmFzLWVucC9zbG90L3YyIikKICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAg"
    "ICAgIyBzZWxlY3RvciBjb2xsaXNpb24gb3IgZmlsZSBjb3JydXB0aW9uOyBmcm9tIHRoZSBvcGVyYXRvcidzIHBvaW50CiAg"
    "ICAgICAgIyBvZiB2aWV3IHRoaXMgaXMgaW5kaXN0aW5ndWlzaGFibGUgZnJvbSAid3JvbmcgbWFjaGluZSIKICAgICAgICBy"
    "YWlzZSBSdW50aW1lRXJyb3IoRklOR0VSUFJJTlRfTUlTTUFUQ0hfTVNHKQoKICAgIHBheWxvYWQgPSBlbnZlbG9wZVsicGF5"
    "bG9hZCJdCiAgICB0cnk6CiAgICAgICAgcGxhaW4gPSBBRVNHQ00oZGVrKS5kZWNyeXB0KGRlY29kZV9iNjQocGF5bG9hZFsi"
    "bm9uY2UiXSksIGRlY29kZV9iNjQocGF5bG9hZFsiY3QiXSksIGIibmFzLWVucC9wYXlsb2FkL3YyIikKICAgIGV4Y2VwdCBF"
    "eGNlcHRpb246CiAgICAgICAgcmFpc2UgUnVudGltZUVycm9yKEZJTkdFUlBSSU5UX01JU01BVENIX01TRykKICAgIHJldHVy"
    "biBqc29uLmxvYWRzKHBsYWluKQoKCmRlZiBsb2FkX2NvbmZpZygpOgogICAgaWYgQ09ORklHX01PREUgPT0gImVudmVsb3Bl"
    "IjoKICAgICAgICByZXR1cm4gbG9hZF9jb25maWdfZW52ZWxvcGUoKQogICAgcmV0dXJuIGxvYWRfY29uZmlnX2xlZ2FjeSgp"
    "CgoKZGVmIHJlcXVpcmVfcm9vdCgpOgogICAgaWYgb3MuZ2V0ZXVpZCgpICE9IDA6CiAgICAgICAgbG9nZigiZmF0YWw6IG11"
    "c3QgYmUgcnVuIGFzIHJvb3QiKQogICAgICAgIHN5cy5leGl0KDEpCgoKZGVmIGlzX21vdW50ZWQodGFyZ2V0KToKICAgIHRy"
    "eToKICAgICAgICB3aXRoIG9wZW4oIi9wcm9jL21vdW50cyIpIGFzIGY6CiAgICAgICAgICAgIGRhdGEgPSBmLnJlYWQoKQog"
    "ICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBhYnNfdGFyZ2V0ID0gb3MucGF0aC5hYnNwYXRo"
    "KHRhcmdldCkKICAgIGZvciBsaW5lIGluIGRhdGEuc3BsaXRsaW5lcygpOgogICAgICAgIGZpZWxkcyA9IGxpbmUuc3BsaXQo"
    "KQogICAgICAgIGlmIGxlbihmaWVsZHMpID49IDIgYW5kIGZpZWxkc1sxXSBpbiAoYWJzX3RhcmdldCwgdGFyZ2V0KToKICAg"
    "ICAgICAgICAgcmV0dXJuIFRydWUKICAgIHJldHVybiBGYWxzZQoKCmRlZiBoYXZlX2NtZChuYW1lKToKICAgIHJldHVybiB3"
    "aGljaChuYW1lKSBpcyBub3QgTm9uZQoKCmRlZiBlbnN1cmVfZGVwcyhjZmcpOgogICAgaWYgY2ZnWyJwcm90b2NvbCJdID09"
    "ICJjaWZzIiBhbmQgbm90IGhhdmVfY21kKCJtb3VudC5jaWZzIik6CiAgICAgICAgaWYgY2ZnLmdldCgiaW5zdGFsbF9kZXBz"
    "IikgYW5kIGhhdmVfY21kKCJhcHQtZ2V0Iik6CiAgICAgICAgICAgIGxvZ2YoIm1vdW50LmNpZnMgbWlzc2luZzsgaW5zdGFs"
    "bGluZyBjaWZzLXV0aWxzIC4uLiIpCiAgICAgICAgICAgIGVudiA9IGRpY3Qob3MuZW52aXJvbiwgREVCSUFOX0ZST05URU5E"
    "PSJub25pbnRlcmFjdGl2ZSIpCiAgICAgICAgICAgIHIgPSBzdWJwcm9jZXNzLnJ1bihbImFwdC1nZXQiLCAiaW5zdGFsbCIs"
    "ICIteSIsICJjaWZzLXV0aWxzIl0sCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgZW52PWVudiwgY2FwdHVyZV9v"
    "dXRwdXQ9VHJ1ZSwgdGV4dD1UcnVlKQogICAgICAgICAgICBpZiByLnJldHVybmNvZGUgIT0gMDoKICAgICAgICAgICAgICAg"
    "IGxvZ2YoZiJ3YXJuOiBjaWZzLXV0aWxzIGluc3RhbGwgZmFpbGVkOiB7ci5yZXR1cm5jb2RlfVxue3Iuc3Rkb3V0fXtyLnN0"
    "ZGVycn0iKQogICAgICAgIGVsc2U6CiAgICAgICAgICAgIGxvZ2YoIndhcm46IG1vdW50LmNpZnMgbm90IGZvdW5kOyBpbnN0"
    "YWxsIGNpZnMtdXRpbHMgKGFwdC1nZXQgaW5zdGFsbCBjaWZzLXV0aWxzKSIpCgoKZGVmIGJ1aWxkX3NvdXJjZShjZmcsIG0p"
    "OgogICAgaWYgY2ZnWyJwcm90b2NvbCJdID09ICJuZnMiOgogICAgICAgIHJldHVybiBmJ3tjZmdbImhvc3QiXX06e21bInJl"
    "bW90ZSJdfScKICAgIHJlbSA9IG1bInJlbW90ZSJdLmxzdHJpcCgiLyIpCiAgICByZXR1cm4gZicvL3tjZmdbImhvc3QiXX0v"
    "e3JlbX0nCgoKZGVmIG1vdW50X29uZShjZmcsIG0sIGlkeCk6CiAgICBpZiBpc19tb3VudGVkKG1bImxvY2FsIl0pOgogICAg"
    "ICAgIGxvZ2YoZiJtb3VudCAje2lkeH06IGFscmVhZHkgbW91bnRlZCIpCiAgICAgICAgcmV0dXJuIFRydWUKICAgIHRyeToK"
    "ICAgICAgICBvcy5tYWtlZGlycyhtWyJsb2NhbCJdLCBtb2RlPTBvNzU1LCBleGlzdF9vaz1UcnVlKQogICAgZXhjZXB0IE9T"
    "RXJyb3I6CiAgICAgICAgbG9nZihmIm1vdW50ICN7aWR4fTogbWtkaXIgZmFpbGVkIikKICAgICAgICByZXR1cm4gRmFsc2UK"
    "CiAgICBvcHRzID0gY2ZnLmdldCgiZGVmYXVsdF9vcHRpb25zIiwgIiIpCiAgICBpZiBtLmdldCgib3B0aW9ucyIsICIiKS5z"
    "dHJpcCgpOgogICAgICAgIG9wdHMgPSBtWyJvcHRpb25zIl0KCiAgICBzcmMgPSBidWlsZF9zb3VyY2UoY2ZnLCBtKQogICAg"
    "aWYgY2ZnWyJwcm90b2NvbCJdID09ICJjaWZzIjoKICAgICAgICBwYXJ0cyA9IFtdCiAgICAgICAgaWYgb3B0czoKICAgICAg"
    "ICAgICAgcGFydHMuYXBwZW5kKG9wdHMpCiAgICAgICAgcGFydHMuYXBwZW5kKCJ1c2VybmFtZT0iICsgY2ZnWyJ1c2VybmFt"
    "ZSJdKQogICAgICAgIGlmIGNmZy5nZXQoImRvbWFpbiIpOgogICAgICAgICAgICBwYXJ0cy5hcHBlbmQoImRvbWFpbj0iICsg"
    "Y2ZnWyJkb21haW4iXSkKICAgICAgICBmdWxsID0gIiwiLmpvaW4ocGFydHMpCiAgICAgICAgZW52ID0gZGljdChvcy5lbnZp"
    "cm9uLCBQQVNTV0Q9Y2ZnLmdldCgicGFzc3dvcmQiLCAiIikpCiAgICAgICAgY21kID0gWyJtb3VudC5jaWZzIiwgc3JjLCBt"
    "WyJsb2NhbCJdLCAiLW8iLCBmdWxsXQogICAgZWxzZToKICAgICAgICBhcmdzID0gWyItdCIsICJuZnMiXQogICAgICAgIGlm"
    "IG9wdHM6CiAgICAgICAgICAgIGFyZ3MgKz0gWyItbyIsIG9wdHNdCiAgICAgICAgYXJncyArPSBbc3JjLCBtWyJsb2NhbCJd"
    "XQogICAgICAgIGNtZCA9IFsibW91bnQiXSArIGFyZ3MKICAgICAgICBlbnYgPSBvcy5lbnZpcm9uLmNvcHkoKQoKICAgICMg"
    "RGVsaWJlcmF0ZWx5IGRvbid0IGxvZyBjbWQvc3JjL21bImxvY2FsIl0gb3IgdGhlIHN1YnByb2Nlc3MncyBvd24KICAgICMg"
    "c3Rkb3V0L3N0ZGVycjogbW91bnQgdG9vbCBlcnJvciB0ZXh0IGNhbiBpdHNlbGYgZW1iZWQgdGhlIE5BUyBob3N0CiAgICAj"
    "IG9yIHNoYXJlIHBhdGgsIGFuZCB0aGlzIHByb2plY3QncyBwb2xpY3kgaXMgdG8gbmV2ZXIgc3VyZmFjZSBOQVMKICAgICMg"
    "aWRlbnRpZnlpbmcgZGV0YWlscyBpbiBsb2dzIChqb3VybmFsY3RsIGV0Yy4pIOKAlCBvbmx5IHN1Y2Nlc3MvZmFpbHVyZS4K"
    "ICAgIHIgPSBzdWJwcm9jZXNzLnJ1bihjbWQsIGVudj1lbnYsIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRleHQ9VHJ1ZSkKICAg"
    "IGlmIHIucmV0dXJuY29kZSAhPSAwOgogICAgICAgIGxvZ2YoZiJtb3VudCAje2lkeH06IGZhaWxlZCAoZXhpdCBjb2RlIHty"
    "LnJldHVybmNvZGV9KSIpCiAgICAgICAgcmV0dXJuIEZhbHNlCiAgICBsb2dmKGYibW91bnQgI3tpZHh9OiBtb3VudGVkIikK"
    "ICAgIHJldHVybiBUcnVlCgoKZGVmIG9uZXNob3QoKToKICAgIHJlcXVpcmVfcm9vdCgpCiAgICB0cnk6CiAgICAgICAgY2Zn"
    "ID0gbG9hZF9jb25maWcoKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIGxvZ2YoZiJmYXRhbDoge2V9IikK"
    "ICAgICAgICByZXR1cm4gMgogICAgZW5zdXJlX2RlcHMoY2ZnKQoKICAgIGF0dGVtcHRzID0gY2ZnLmdldCgicmV0cnlfYXR0"
    "ZW1wdHMiKSBvciAxCiAgICBpZiBhdHRlbXB0cyA8IDE6CiAgICAgICAgYXR0ZW1wdHMgPSAxCiAgICBkZWxheSA9IGNmZy5n"
    "ZXQoInJldHJ5X2RlbGF5X3NlYyIpIG9yIDUKICAgIGlmIGRlbGF5IDw9IDA6CiAgICAgICAgZGVsYXkgPSA1CgogICAgdG90"
    "YWwgPSBsZW4oY2ZnWyJtb3VudHMiXSkKICAgIHBlbmRpbmcgPSBsaXN0KGVudW1lcmF0ZShjZmdbIm1vdW50cyJdLCBzdGFy"
    "dD0xKSkKICAgIGF0dGVtcHQgPSAxCiAgICB3aGlsZSBhdHRlbXB0IDw9IGF0dGVtcHRzIGFuZCBwZW5kaW5nOgogICAgICAg"
    "IHN0aWxsX3BlbmRpbmcgPSBbXQogICAgICAgIGZvciBpZHgsIG0gaW4gcGVuZGluZzoKICAgICAgICAgICAgaWYgbm90IG1v"
    "dW50X29uZShjZmcsIG0sIGlkeCk6CiAgICAgICAgICAgICAgICBzdGlsbF9wZW5kaW5nLmFwcGVuZCgoaWR4LCBtKSkKICAg"
    "ICAgICBwZW5kaW5nID0gc3RpbGxfcGVuZGluZwogICAgICAgIGlmIHBlbmRpbmcgYW5kIGF0dGVtcHQgPCBhdHRlbXB0czoK"
    "ICAgICAgICAgICAgZCA9IG1pbihkZWxheSAqIGF0dGVtcHQsIDYwKQogICAgICAgICAgICBsb2dmKGYie2xlbihwZW5kaW5n"
    "KX0ve3RvdGFsfSBtb3VudChzKSBwZW5kaW5nLCByZXRyeWluZyBpbiB7ZH1zIC4uLiIpCiAgICAgICAgICAgIHRpbWUuc2xl"
    "ZXAoZCkKICAgICAgICBhdHRlbXB0ICs9IDEKCiAgICBpZiBwZW5kaW5nOgogICAgICAgIGxvZ2YoZiJnaXZpbmcgdXA6IHts"
    "ZW4ocGVuZGluZyl9L3t0b3RhbH0gbW91bnQocykgbm90IG1vdW50ZWQiKQogICAgICAgIHJldHVybiAxICAjIG5vbnplcm8s"
    "IGJ1dCBib290IGlzIHVuYWZmZWN0ZWQgYmVjYXVzZSBub3RoaW5nIGRlcGVuZHMgb24gdGhpcyB1bml0CiAgICBsb2dmKGYi"
    "YWxsIHt0b3RhbH0gbW91bnQocykgdXAiKQogICAgcmV0dXJuIDAKCgpkZWYgc3RhdHVzKCk6CiAgICB0cnk6CiAgICAgICAg"
    "Y2ZnID0gbG9hZF9jb25maWcoKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIGxvZ2YoZiJmYXRhbDoge2V9"
    "IikKICAgICAgICByZXR1cm4gMgogICAgdG90YWwgPSBsZW4oY2ZnWyJtb3VudHMiXSkKICAgIG1vdW50ZWQgPSBzdW0oMSBm"
    "b3IgbSBpbiBjZmdbIm1vdW50cyJdIGlmIGlzX21vdW50ZWQobVsibG9jYWwiXSkpCiAgICBwcmludChmInttb3VudGVkfS97"
    "dG90YWx9IG1vdW50KHMpIGFjdGl2ZSIpCiAgICByZXR1cm4gMAoKCmRlZiBzZWxmdGVzdCgpOgogICAgaWYgQ09ORklHX01P"
    "REUgPT0gImVudmVsb3BlIjoKICAgICAgICB0cnk6CiAgICAgICAgICAgIGZpbmdlcnByaW50LCB1c2VkLCBza2lwcGVkID0g"
    "Y29sbGVjdF9maW5nZXJwcmludCgpCiAgICAgICAgZXhjZXB0IFN5c3RlbUV4aXQgYXMgZToKICAgICAgICAgICAgbG9nZihm"
    "InNlbGZ0ZXN0IEZBSUxFRDoge2V9IikKICAgICAgICAgICAgcmV0dXJuIDIKICAgICAgICBzZWxlY3RvciA9IGZpbmdlcnBy"
    "aW50X3NlbGVjdG9yKGZpbmdlcnByaW50KQogICAgICAgIGVudmVsb3BlID0ganNvbi5sb2FkcyhkZWNvZGVfYjY0KEJMT0Jf"
    "RU5WRUxPUEUpKQogICAgICAgIHNsb3RfZm91bmQgPSBhbnkoc1sic2VsZWN0b3IiXSA9PSBzZWxlY3RvciBmb3IgcyBpbiBl"
    "bnZlbG9wZVsic2xvdHMiXSkKICAgICAgICBwcmludChmImZpbmdlcnByaW50IGNvbGxlY3RlZCBPSzogcHJlZml4PXtmaW5n"
    "ZXJwcmludFs6OF19Li4uIGNvbXBvbmVudHMgdXNlZD17JywnLmpvaW4odXNlZCl9IikKICAgICAgICBpZiBza2lwcGVkOgog"
    "ICAgICAgICAgICBwcmludChmImNvbXBvbmVudHMgc2tpcHBlZDogeycsJy5qb2luKHNraXBwZWQpfSIpCiAgICAgICAgcHJp"
    "bnQoZiJzbG90IG1hdGNoOiB7J0ZPVU5EJyBpZiBzbG90X2ZvdW5kIGVsc2UgJ05PVCBGT1VORCd9IikKICAgICAgICBpZiBu"
    "b3Qgc2xvdF9mb3VuZDoKICAgICAgICAgICAgbG9nZihmInNlbGZ0ZXN0IEZBSUxFRDoge0ZJTkdFUlBSSU5UX01JU01BVENI"
    "X01TR30iKQogICAgICAgICAgICByZXR1cm4gMgogICAgdHJ5OgogICAgICAgIGNmZyA9IGxvYWRfY29uZmlnKCkKICAgIGV4"
    "Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBsb2dmKGYic2VsZnRlc3QgRkFJTEVEOiB7ZX0iKQogICAgICAgIHJldHVy"
    "biAyCiAgICBwcmludChmJ2NvbmZpZyBkZWNyeXB0ZWQgT0s6IHByb3RvY29sPXtjZmdbInByb3RvY29sIl19IG1vdW50cz17"
    "bGVuKGNmZ1sibW91bnRzIl0pfScpCiAgICByZXR1cm4gMAoKClVOSVRfVEVNUExBVEUgPSAiIiJbVW5pdF0KRGVzY3JpcHRp"
    "b249TkFTIGF1dG8gbW91bnQgKG5hcy1lbnAtbW91bnQpCkFmdGVyPW5ldHdvcmstb25saW5lLnRhcmdldApXYW50cz1uZXR3"
    "b3JrLW9ubGluZS50YXJnZXQKIyBJbnRlbnRpb25hbGx5IG5vIFJlcXVpcmVzIGZyb20gb3RoZXIgdW5pdHMgLT4gZmFpbHVy"
    "ZXMgbmV2ZXIgYmxvY2sgYm9vdC4KU3RhcnRMaW1pdEludGVydmFsU2VjPTAKCltTZXJ2aWNlXQpUeXBlPW9uZXNob3QKUmVt"
    "YWluQWZ0ZXJFeGl0PXllcwpFeGVjU3RhcnQ9e3B5dGhvbn0ge3NjcmlwdH0gLS1vbmVzaG90CiMgQm91bmRlZCBzbyBhIGRl"
    "YWQgTkFTIGNhbiBuZXZlciBoYW5nIGJvb3Q7IHJldHJpZXMgaGFwcGVuIGluc2lkZSB0aGlzIGJ1ZGdldC4KIyBGaW5nZXJw"
    "cmludCBtaXNtYXRjaCAoYmluZGluZy5tb2RlPW1hY2hpbmUpIGlzIGEgcGVybWFuZW50IGVycm9yLCBub3QgYQojIHRyYW5z"
    "aWVudCBvbmUsIHNvIGl0IG11c3Qgbm90IHRyaWdnZXIgYSBzeXN0ZW1kLWxldmVsIHJldHJ5IGxvb3AgZWl0aGVyOgojIG5v"
    "IFJlc3RhcnQ9IGlzIHNldCBoZXJlLCBhbmQgU3RhcnRMaW1pdEludGVydmFsU2VjPTAgYWJvdmUgZGlzYWJsZXMgdGhlCiMg"
    "dW5pdCdzIGF1dG9tYXRpYyByZXN0YXJ0LXJhdGUtbGltaXQgbWFjaGluZXJ5IGVudGlyZWx5LgpUaW1lb3V0U3RhcnRTZWM9"
    "MTUwCgpbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKIiIiCgoKZGVmIGluc3RhbGxfc2VydmljZSgpOgog"
    "ICAgcmVxdWlyZV9yb290KCkKICAgIHRyeToKICAgICAgICBsb2FkX2NvbmZpZygpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFz"
    "IGU6CiAgICAgICAgbG9nZihmInJlZnVzaW5nIHRvIGluc3RhbGw6IHtlfSIpCiAgICAgICAgcmV0dXJuIDIKICAgIG9zLm1h"
    "a2VkaXJzKElOU1RBTExfRElSLCBtb2RlPTBvNzAwLCBleGlzdF9vaz1UcnVlKQogICAgdGFyZ2V0ID0gb3MucGF0aC5qb2lu"
    "KElOU1RBTExfRElSLCBCSU5fTkFNRSkKICAgIHNlbGZfcGF0aCA9IG9zLnBhdGguYWJzcGF0aChfX2ZpbGVfXykKICAgIGlm"
    "IHNlbGZfcGF0aCAhPSB0YXJnZXQ6CiAgICAgICAgd2l0aCBvcGVuKHNlbGZfcGF0aCwgInJiIikgYXMgZjoKICAgICAgICAg"
    "ICAgZGF0YSA9IGYucmVhZCgpCiAgICAgICAgd2l0aCBvcGVuKHRhcmdldCwgIndiIikgYXMgZjoKICAgICAgICAgICAgZi53"
    "cml0ZShkYXRhKQogICAgICAgIG9zLmNobW9kKHRhcmdldCwgMG83MDApCiAgICAgICAgbG9nZihmImluc3RhbGxlZCBzY3Jp"
    "cHQgdG8ge3RhcmdldH0iKQoKICAgIHVuaXQgPSBVTklUX1RFTVBMQVRFLmZvcm1hdChweXRob249c3lzLmV4ZWN1dGFibGUs"
    "IHNjcmlwdD10YXJnZXQpCiAgICB1bml0X3BhdGggPSBmIi9ldGMvc3lzdGVtZC9zeXN0ZW0ve1NFUlZJQ0VfTkFNRX0iCiAg"
    "ICB3aXRoIG9wZW4odW5pdF9wYXRoLCAidyIpIGFzIGY6CiAgICAgICAgZi53cml0ZSh1bml0KQogICAgbG9nZihmIndyb3Rl"
    "IHt1bml0X3BhdGh9IikKICAgIGZvciBhcmdzIGluIChbImRhZW1vbi1yZWxvYWQiXSwgWyJlbmFibGUiLCBTRVJWSUNFX05B"
    "TUVdLCBbInN0YXJ0IiwgU0VSVklDRV9OQU1FXSk6CiAgICAgICAgciA9IHN1YnByb2Nlc3MucnVuKFsic3lzdGVtY3RsIl0g"
    "KyBhcmdzLCBjYXB0dXJlX291dHB1dD1UcnVlLCB0ZXh0PVRydWUpCiAgICAgICAgaWYgci5yZXR1cm5jb2RlICE9IDA6CiAg"
    "ICAgICAgICAgIGxvZ2YoZiJ3YXJuOiBzeXN0ZW1jdGwge2FyZ3N9OiB7ci5yZXR1cm5jb2RlfTogeyhyLnN0ZG91dCArIHIu"
    "c3RkZXJyKS5zdHJpcCgpfSIpCiAgICBsb2dmKGYic2VydmljZSBpbnN0YWxsZWQgYW5kIHN0YXJ0ZWQuIENoZWNrOiBzeXN0"
    "ZW1jdGwgc3RhdHVzIHtTRVJWSUNFX05BTUV9IikKICAgIHJldHVybiAwCgoKZGVmIHVuaW5zdGFsbCgpOgogICAgcmVxdWly"
    "ZV9yb290KCkKICAgIHN1YnByb2Nlc3MucnVuKFsic3lzdGVtY3RsIiwgImRpc2FibGUiLCAiLS1ub3ciLCBTRVJWSUNFX05B"
    "TUVdLCBjYXB0dXJlX291dHB1dD1UcnVlKQogICAgdHJ5OgogICAgICAgIG9zLnJlbW92ZShmIi9ldGMvc3lzdGVtZC9zeXN0"
    "ZW0ve1NFUlZJQ0VfTkFNRX0iKQogICAgZXhjZXB0IE9TRXJyb3I6CiAgICAgICAgcGFzcwogICAgc3VicHJvY2Vzcy5ydW4o"
    "WyJzeXN0ZW1jdGwiLCAiZGFlbW9uLXJlbG9hZCJdLCBjYXB0dXJlX291dHB1dD1UcnVlKQogICAgdHJ5OgogICAgICAgIGNm"
    "ZyA9IGxvYWRfY29uZmlnKCkKICAgICAgICB1bm1vdW50ZWQgPSAwCiAgICAgICAgZm9yIG0gaW4gY2ZnWyJtb3VudHMiXToK"
    "ICAgICAgICAgICAgaWYgaXNfbW91bnRlZChtWyJsb2NhbCJdKToKICAgICAgICAgICAgICAgIHIgPSBzdWJwcm9jZXNzLnJ1"
    "bihbInVtb3VudCIsIG1bImxvY2FsIl1dLCBjYXB0dXJlX291dHB1dD1UcnVlLCB0ZXh0PVRydWUpCiAgICAgICAgICAgICAg"
    "ICBpZiByLnJldHVybmNvZGUgPT0gMDoKICAgICAgICAgICAgICAgICAgICB1bm1vdW50ZWQgKz0gMQogICAgICAgIGxvZ2Yo"
    "ZiJ1bm1vdW50ZWQge3VubW91bnRlZH0gc2hhcmUocykiKQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICBwYXNzCiAg"
    "ICBsb2dmKCJ1bmluc3RhbGxlZCIpCiAgICByZXR1cm4gMAoKCmRlZiB1c2FnZSgpOgogICAgcHJpbnQoIiIibmFzLWVucC1t"
    "b3VudAogIChubyBhcmdzKSAvIC0tb25lc2hvdCAgIG1vdW50IGFsbCBzaGFyZXMgb25jZSAod2l0aCBpbnRlcm5hbCByZXRy"
    "aWVzKQogIC0taW5zdGFsbC1zZXJ2aWNlICAgICAgIGluc3RhbGwgJiBlbmFibGUgc3lzdGVtZCBib290IHNlcnZpY2UKICAt"
    "LXVuaW5zdGFsbCAgICAgICAgICAgICBzdG9wIHNlcnZpY2UsIHJlbW92ZSB1bml0LCB1bm1vdW50IHNoYXJlcwogIC0tc3Rh"
    "dHVzICAgICAgICAgICAgICAgIHNob3cgbW91bnQgc3RhdHVzCiAgLS1zZWxmdGVzdCAgICAgICAgICAgICAgdmVyaWZ5IGVt"
    "YmVkZGVkIGNvbmZpZyBkZWNyeXB0cyAobm8gc2VjcmV0cyBwcmludGVkKSIiIikKCgpkZWYgbWFpbigpOgogICAgbW9kZSA9"
    "IHN5cy5hcmd2WzFdIGlmIGxlbihzeXMuYXJndikgPiAxIGVsc2UgIi0tb25lc2hvdCIKICAgIGlmIG1vZGUgaW4gKCItLW9u"
    "ZXNob3QiLCAiIik6CiAgICAgICAgc3lzLmV4aXQob25lc2hvdCgpKQogICAgZWxpZiBtb2RlID09ICItLWluc3RhbGwtc2Vy"
    "dmljZSI6CiAgICAgICAgc3lzLmV4aXQoaW5zdGFsbF9zZXJ2aWNlKCkpCiAgICBlbGlmIG1vZGUgPT0gIi0tdW5pbnN0YWxs"
    "IjoKICAgICAgICBzeXMuZXhpdCh1bmluc3RhbGwoKSkKICAgIGVsaWYgbW9kZSA9PSAiLS1zdGF0dXMiOgogICAgICAgIHN5"
    "cy5leGl0KHN0YXR1cygpKQogICAgZWxpZiBtb2RlID09ICItLXNlbGZ0ZXN0IjoKICAgICAgICBzeXMuZXhpdChzZWxmdGVz"
    "dCgpKQogICAgZWxpZiBtb2RlIGluICgiLWgiLCAiLS1oZWxwIiwgImhlbHAiKToKICAgICAgICB1c2FnZSgpCiAgICBlbHNl"
    "OgogICAgICAgIHVzYWdlKCkKICAgICAgICBzeXMuZXhpdCgyKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6CiAgICBt"
    "YWluKCkK"
)

def py_client_template() -> str:
    src = base64.b64decode("".join(PY_CLIENT_TEMPLATE_B64)).decode()
    marker = "# __FINGERPRINT_LOGIC__"
    assert marker in src, "client template missing fingerprint-logic splice marker"
    return src.replace(marker, FINGERPRINT_LOGIC_SRC)

# ------------------------------------------------------------------ collect
FP_HEX_RE = re.compile(r"^[0-9a-f]{64}$")

def prompt_binding() -> dict:
    print(
        "\nMachine binding: without it, anyone who obtains the generated "
        "script can decrypt it. With it, the script only decrypts on "
        "machines whose fingerprint you list below (collect one first with "
        "--emit-collector on each target machine).\n"
    )
    mode = ""
    while mode not in ("machine", "none"):
        mode = (input("Binding mode [machine/none]: ").strip().lower())
    if mode == "none":
        return {"mode": "none", "fingerprints": []}
    print("Paste one 64-hex-char fingerprint per line. Empty line finishes.")
    fps = []
    while True:
        line = input(f"  fingerprint [{len(fps)+1}]: ").strip()
        if not line:
            break
        fps.append(line)
    if not fps:
        sys.exit("binding.mode=machine requires at least one fingerprint")
    return {"mode": "machine", "fingerprints": fps}

def prompt_config() -> dict:
    print("=== nas-enp-mount configuration ===\n")
    protocol = ""
    while protocol not in ("cifs", "nfs"):
        protocol = (input("Protocol [cifs/nfs] (default cifs): ").strip().lower() or "cifs")
    host = input("NAS IP or hostname (e.g. 192.168.1.50): ").strip()

    username = password = domain = ""
    if protocol == "cifs":
        username = input("SMB username: ").strip()
        password = getpass.getpass("SMB password (input hidden): ")
        domain = input("SMB domain/workgroup (optional, Enter to skip): ").strip()

    if protocol == "cifs":
        default_options = (input(
            "Default mount options "
            "(Enter for 'vers=3.0,iocharset=utf8,uid=0,gid=0,file_mode=0644,dir_mode=0755'): "
        ).strip() or "vers=3.0,iocharset=utf8,uid=0,gid=0,file_mode=0644,dir_mode=0755")
    else:
        default_options = (input(
            "Default NFS options (Enter for 'vers=4,soft,timeo=50,retrans=3'): "
        ).strip() or "vers=4,soft,timeo=50,retrans=3")

    mounts = []
    print("\nNow add mount mappings. Empty remote path finishes.\n")
    while True:
        if protocol == "cifs":
            remote = input(f"  Remote share/path on NAS (e.g. 'Media/Movies') [{len(mounts)+1}]: ").strip()
        else:
            remote = input(f"  Remote export path on NAS (e.g. '/volume1/media') [{len(mounts)+1}]: ").strip()
        if not remote:
            break
        local = input("  Local mount point on client (e.g. /mnt/nas-movies): ").strip()
        if not local:
            print("  local mount point required, skipping.")
            continue
        opts = input("  Per-mount options (Enter to use default): ").strip()
        mounts.append({"remote": remote, "local": local, "options": opts})
        print()

    if not mounts:
        sys.exit("No mounts configured, aborting.")

    retry_attempts = int(input("Retry attempts on failure (default 5): ").strip() or "5")
    retry_delay = int(input("Base retry delay seconds (default 5): ").strip() or "5")
    install_deps = (input("Auto-install cifs-utils if missing? [Y/n]: ").strip().lower() or "y") == "y"
    binding = prompt_binding()

    return {
        "protocol": protocol, "host": host, "username": username,
        "password": password, "domain": domain,
        "default_options": default_options, "mounts": mounts,
        "retry_attempts": retry_attempts, "retry_delay_sec": retry_delay,
        "install_deps": install_deps, "binding": binding,
    }

def validate(cfg: dict):
    if cfg.get("protocol") not in ("cifs", "nfs"):
        sys.exit("protocol must be cifs or nfs")
    if not cfg.get("host"):
        sys.exit("host is required")
    if cfg["protocol"] == "cifs" and not cfg.get("username"):
        sys.exit("cifs requires a username")
    if not cfg.get("mounts"):
        sys.exit("at least one mount is required")
    for m in cfg["mounts"]:
        if not m.get("remote") or not m.get("local"):
            sys.exit(f"each mount needs 'remote' and 'local': {m}")
    cfg.setdefault("domain", "")
    cfg.setdefault("default_options", "")
    cfg.setdefault("retry_attempts", 5)
    cfg.setdefault("retry_delay_sec", 5)
    cfg.setdefault("install_deps", True)
    cfg.setdefault("password", "")
    validate_binding(cfg)

def validate_binding(cfg: dict):
    binding = cfg.get("binding")
    if not isinstance(binding, dict) or "mode" not in binding:
        sys.exit(
            "binding.mode is required (no default). Choose one:\n"
            '  {"binding": {"mode": "machine", "fingerprints": ["<64 hex>", ...]}}\n'
            '    -> decrypts only on the listed machines (see --emit-collector)\n'
            '  {"binding": {"mode": "none"}}\n'
            '    -> compatibility mode, NO leak protection'
        )
    mode = binding.get("mode")
    if mode not in ("machine", "none"):
        sys.exit('binding.mode must be "machine" or "none"')
    fps = binding.get("fingerprints") or []
    if mode == "none":
        binding["fingerprints"] = []
        return
    if not fps:
        sys.exit("binding.mode=machine requires a non-empty binding.fingerprints list")
    seen = set()
    deduped = []
    for fp in fps:
        fp_norm = str(fp).strip().lower()
        if not FP_HEX_RE.match(fp_norm):
            sys.exit(f"invalid fingerprint (must be 64 hex chars): {fp!r}")
        if fp_norm in seen:
            print(f"[warn] duplicate fingerprint dropped: {fp_norm[:8]}...", file=sys.stderr)
            continue
        seen.add(fp_norm)
        deduped.append(fp_norm)
    binding["fingerprints"] = deduped

# ------------------------------------------------------------------ crypto
def encrypt_config_legacy(cfg: dict) -> dict:
    plain = json.dumps(cfg, separators=(",", ":")).encode()
    key = os.urandom(32)
    pad = os.urandom(32)
    key_a = bytes(a ^ b for a, b in zip(key, pad))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plain, None)
    b = lambda x: base64.b64encode(x).decode()
    return {"cipher": b(ct), "nonce": b(nonce), "keya": b(key_a), "keypad": b(pad)}

def build_envelope(cfg: dict, fingerprints: list) -> dict:
    """Multi-recipient envelope: one random DEK encrypts the config once;
    each fingerprint wraps that same DEK via its own Scrypt-derived KEK.
    See DESIGN.md 'Envelope format'."""
    dek = os.urandom(32)
    payload_nonce = os.urandom(12)
    plain = json.dumps(cfg, separators=(",", ":")).encode()
    payload_ct = AESGCM(dek).encrypt(payload_nonce, plain, b"nas-enp/payload/v2")

    b = lambda x: base64.b64encode(x).decode()
    slots = []
    for fp in fingerprints:
        selector = fingerprint_selector(fp)
        salt = os.urandom(16)
        kek = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(fp.encode())
        slot_nonce = os.urandom(12)
        wrapped_dek = AESGCM(kek).encrypt(slot_nonce, dek, b"nas-enp/slot/v2")
        slots.append({
            "selector": selector, "salt": b(salt),
            "nonce": b(slot_nonce), "wrapped_dek": b(wrapped_dek),
        })
    random.shuffle(slots)  # slot position must not leak generation order

    return {
        "v": 2,
        "kdf": {"algo": "scrypt", "n": 32768, "r": 8, "p": 1, "dklen": 32},
        "slots": slots,
        "payload": {"nonce": b(payload_nonce), "ct": b(payload_ct)},
    }

def fingerprint_selector(fingerprint: str) -> str:
    return hashlib.sha256((fingerprint + "nas-enp/selector/v2").encode()).digest()[:8].hex()

def fill_template(cfg: dict) -> str:
    """Fill the client template per cfg['binding']['mode'] and return the
    finished source. Both blob placeholder sets are always present in the
    template; the unused set is filled with harmless empty strings."""
    binding = cfg["binding"]
    src = py_client_template()
    if binding["mode"] == "machine":
        envelope = build_envelope(cfg, binding["fingerprints"])
        env_b64 = base64.b64encode(json.dumps(envelope).encode()).decode()
        return (src.replace("__CONFIG_MODE__", "envelope")
                   .replace("__CIPHERTEXT__", "")
                   .replace("__NONCE__", "")
                   .replace("__KEYA__", "")
                   .replace("__KEYPAD__", "")
                   .replace("__ENVELOPE__", env_b64))
    blob = encrypt_config_legacy(cfg)
    return (src.replace("__CONFIG_MODE__", "legacy")
               .replace("__CIPHERTEXT__", blob["cipher"])
               .replace("__NONCE__", blob["nonce"])
               .replace("__KEYA__", blob["keya"])
               .replace("__KEYPAD__", blob["keypad"])
               .replace("__ENVELOPE__", ""))

def self_check_no_leak(src: str, cfg: dict, out_path: str):
    """Post-generation guardrail (guide 6.4): scan the written file for
    plaintext or base64 leaks of host/username/password. Abort + delete
    the output on any hit rather than ship a broken generator silently."""
    needles = []
    for field in ("host", "username", "password"):
        val = cfg.get(field)
        if val:
            needles.append(str(val))
            needles.append(base64.b64encode(str(val).encode()).decode())
    hits = [n for n in needles if n and n in src]
    if hits:
        try:
            os.remove(out_path)
        except OSError:
            pass
        sys.exit(
            f"FATAL: generation self-check found {len(hits)} plaintext/base64 "
            f"leak(s) in the written client script. Output deleted: {out_path}\n"
            "This means the generator itself has a bug — do not ignore this."
        )

COLLECTOR_HEADER = '''\
#!/usr/bin/env python3
"""
nas-enp-fingerprint — standalone hardware fingerprint collector

Run as root on the TARGET machine before generating a machine-bound
nas-enp-mount client. Prints a 64-hex-char fingerprint; paste it into
nas-enp-gen's "binding.fingerprints" list (or the GUI's fingerprint box).

Zero third-party dependencies — copy this single file anywhere and run it
with any Python 3. Contains no credentials and no NAS information.
"""
import hashlib
import os
import re

'''

COLLECTOR_MAIN = '''

def main():
    fingerprint, used, skipped = collect_fingerprint()
    print(f"fingerprint: {fingerprint}")
    print(f"components used: {', '.join(used)}")
    if skipped:
        print(f"components skipped: {', '.join(skipped)}")


if __name__ == "__main__":
    main()
'''

def emit_collector(out_path: str):
    src = COLLECTOR_HEADER + FINGERPRINT_LOGIC_SRC + COLLECTOR_MAIN
    out_abs = os.path.abspath(out_path)
    with open(out_abs, "w", newline="\n") as f:
        f.write(src)
    os.chmod(out_abs, 0o755)
    print(f"[emit] Fingerprint collector written to: {out_abs}")
    print(f"Copy it to each target machine and run (as root): python3 {os.path.basename(out_abs)}")

def deploy_instructions(out_path: str, lang: str = "en") -> str:
    name = os.path.basename(out_path)
    if lang == "zh":
        return (
            "在每台 Linux 客户端上部署（以 root 身份）：\n"
            "  mkdir -p /root/nas-enp-mount\n"
            f"  cp {name} /root/nas-enp-mount/\n"
            f"  python3 /root/nas-enp-mount/{name} --selftest         # 自检\n"
            f"  python3 /root/nas-enp-mount/{name} --install-service  # 开机自启\n"
            "\n提醒：请使用专用、最小权限、可随时吊销的 NAS 账号。"
        )
    return (
        "Deploy on each Linux client (as root):\n"
        "  mkdir -p /root/nas-enp-mount\n"
        f"  cp {name} /root/nas-enp-mount/\n"
        f"  python3 /root/nas-enp-mount/{name} --selftest         # sanity check\n"
        f"  python3 /root/nas-enp-mount/{name} --install-service  # enable at boot\n"
        "\nReminder: use a dedicated, least-privilege, revocable NAS account."
    )

# ------------------------------------------------------------------ i18n
STRINGS = {
    "en": {
        "window_title": "nas-enp-mount generator",
        "language": "Language:",
        "protocol": "Protocol:",
        "host": "NAS host/IP:",
        "username": "Username:",
        "password": "Password:",
        "domain": "Domain (optional):",
        "default_options": "Default mount options:",
        "mounts_label": "Mounts:",
        "add_mount": "Add mount",
        "remove": "Remove",
        "remote_placeholder": "remote path on NAS",
        "local_placeholder": "local mount point",
        "options_placeholder": "per-mount options (optional)",
        "retry_attempts": "Retry attempts:",
        "retry_delay": "Retry delay (sec):",
        "install_deps": "Auto-install cifs-utils if missing",
        "out_path": "Output path:",
        "save_config": "Save config to:",
        "save_config_placeholder": "(optional) also save config JSON to ...",
        "generate": "Generate",
        "invalid_config_title": "Invalid configuration",
        "done_title": "Done",
        "close": "Close",
        "script_written": "Client script written to: {path}\n\n",
        "binding_label": "Machine binding:",
        "binding_machine": "Bind to specific machine(s)",
        "binding_none": "No binding (compatibility mode)",
        "binding_fingerprints_placeholder": "one 64-hex fingerprint per line (see Export collector)",
        "binding_import_file": "Import from file",
        "binding_count": "{n} machine(s) loaded",
        "export_collector": "Export collector",
        "export_collector_saved": "Fingerprint collector written to: {path}",
    },
    "zh": {
        "window_title": "nas-enp-mount 生成器",
        "language": "语言：",
        "protocol": "协议：",
        "host": "NAS 主机/IP：",
        "username": "用户名：",
        "password": "密码：",
        "domain": "域（可选）：",
        "default_options": "默认挂载选项：",
        "mounts_label": "挂载点：",
        "add_mount": "添加挂载",
        "remove": "移除",
        "remote_placeholder": "NAS 上的远程路径",
        "local_placeholder": "本地挂载点",
        "options_placeholder": "单项挂载选项（可选）",
        "retry_attempts": "重试次数：",
        "retry_delay": "重试间隔（秒）：",
        "install_deps": "缺失时自动安装 cifs-utils",
        "out_path": "输出路径：",
        "save_config": "保存配置到：",
        "save_config_placeholder": "（可选）同时保存配置 JSON 到……",
        "generate": "生成",
        "invalid_config_title": "配置无效",
        "done_title": "完成",
        "close": "关闭",
        "script_written": "客户端脚本已写入：{path}\n\n",
        "binding_label": "机器绑定：",
        "binding_machine": "绑定到指定机器",
        "binding_none": "不绑定（兼容模式）",
        "binding_fingerprints_placeholder": "每行一个 64 位十六进制指纹（见“导出采集器”）",
        "binding_import_file": "从文件导入",
        "binding_count": "已载入 {n} 台机器的指纹",
        "export_collector": "导出采集器",
        "export_collector_saved": "采集器已写入：{path}",
    },
}

# validate() (shared with --config/--cli headless paths) always raises English
# messages via sys.exit; this maps the known ones for the GUI's message box
# only. Unrecognized messages fall back to the original English text.
VALIDATE_MSG_ZH = {
    "protocol must be cifs or nfs": "协议必须是 cifs 或 nfs",
    "host is required": "必须填写主机地址",
    "cifs requires a username": "CIFS 协议需要用户名",
    "at least one mount is required": "至少需要一个挂载项",
    "binding.mode=machine requires a non-empty binding.fingerprints list": "选择“绑定到指定机器”时至少需要一个指纹",
}

def translate_validation_msg(msg: str, lang: str) -> str:
    if lang != "zh":
        return msg
    if msg in VALIDATE_MSG_ZH:
        return VALIDATE_MSG_ZH[msg]
    if msg.startswith("each mount needs 'remote' and 'local': "):
        return "每个挂载项都需要 'remote' 和 'local'：" + msg.split(": ", 1)[1]
    return msg

# ------------------------------------------------------------------ gui
def _pip_install(pkg: str):
    r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", pkg],
                        capture_output=True, text=True)
    if r.returncode != 0:
        # pip module may be missing entirely on a minimal image; bootstrap it once.
        subprocess.run([sys.executable, "-m", "ensurepip", "--default-pip"],
                        capture_output=True, text=True)
        r = subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", pkg],
                            capture_output=True, text=True)
    return r

def ensure_pyside6():
    try:
        import PySide6  # noqa: F401
        return
    except ImportError:
        sys.stderr.write("PySide6 missing; installing via pip ...\n")
        r = _pip_install("PySide6")
        if r.returncode != 0:
            sys.exit(f"Missing dependency. Run:  pip install PySide6\n{r.stdout}{r.stderr}")
        try:
            import PySide6  # noqa: F401
        except ImportError:
            sys.exit("PySide6 still not importable after install.")

def launch_gui():
    ensure_pyside6()
    from PySide6.QtWidgets import (
        QApplication, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit,
        QComboBox, QCheckBox, QSpinBox, QPushButton, QLabel, QMessageBox,
        QPlainTextEdit, QDialog, QFileDialog,
    )
    from PySide6.QtCore import QLocale

    class MountRow(QWidget):
        def __init__(self, on_remove, strings):
            super().__init__()
            layout = QHBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            self.remote = QLineEdit()
            self.local = QLineEdit()
            self.options = QLineEdit()
            self.remove_btn = QPushButton()
            self.remove_btn.clicked.connect(lambda: on_remove(self))
            for w in (self.remote, self.local, self.options, self.remove_btn):
                layout.addWidget(w)
            self.retranslate(strings)

        def retranslate(self, strings):
            self.remote.setPlaceholderText(strings["remote_placeholder"])
            self.local.setPlaceholderText(strings["local_placeholder"])
            self.options.setPlaceholderText(strings["options_placeholder"])
            self.remove_btn.setText(strings["remove"])

        def to_dict(self):
            return {"remote": self.remote.text().strip(),
                    "local": self.local.text().strip(),
                    "options": self.options.text().strip()}

    class GeneratorWindow(QWidget):
        def __init__(self):
            super().__init__()
            self.mount_rows = []
            self.lang = "zh" if QLocale.system().name().startswith("zh") else "en"

            root = QVBoxLayout(self)

            lang_row = QHBoxLayout()
            self.lang_label = QLabel()
            self.lang_combo = QComboBox()
            self.lang_combo.addItem("English", "en")
            self.lang_combo.addItem("中文", "zh")
            self.lang_combo.setCurrentIndex(1 if self.lang == "zh" else 0)
            self.lang_combo.currentIndexChanged.connect(self._on_lang_changed)
            lang_row.addWidget(self.lang_label)
            lang_row.addWidget(self.lang_combo)
            lang_row.addStretch()
            root.addLayout(lang_row)

            self.form = QFormLayout()

            self.protocol = QComboBox()
            self.protocol.addItems(["cifs", "nfs"])
            self.protocol.currentTextChanged.connect(self._on_protocol_changed)
            self.form.addRow(" ", self.protocol)

            self.host = QLineEdit()
            self.form.addRow(" ", self.host)

            self.username = QLineEdit()
            self.form.addRow(" ", self.username)

            self.password = QLineEdit()
            self.password.setEchoMode(QLineEdit.Password)
            self.form.addRow(" ", self.password)

            self.domain = QLineEdit()
            self.form.addRow(" ", self.domain)

            self.default_options = QLineEdit()
            self.form.addRow(" ", self.default_options)

            root.addLayout(self.form)
            self.mounts_label = QLabel()
            root.addWidget(self.mounts_label)
            self.mounts_box = QVBoxLayout()
            root.addLayout(self.mounts_box)
            self.add_mount_btn = QPushButton()
            self.add_mount_btn.clicked.connect(self._add_mount_row)
            root.addWidget(self.add_mount_btn)

            self.form2 = QFormLayout()
            self.retry_attempts = QSpinBox()
            self.retry_attempts.setRange(1, 100)
            self.retry_attempts.setValue(5)
            self.form2.addRow(" ", self.retry_attempts)

            self.retry_delay = QSpinBox()
            self.retry_delay.setRange(1, 3600)
            self.retry_delay.setValue(5)
            self.form2.addRow(" ", self.retry_delay)

            self.install_deps = QCheckBox()
            self.install_deps.setChecked(True)
            self.form2.addRow(self.install_deps)

            self.out_path = QLineEdit("nas-enp-mount.py")
            self.form2.addRow(" ", self.out_path)

            self.save_config_path = QLineEdit()
            self.form2.addRow(" ", self.save_config_path)

            root.addLayout(self.form2)

            self.binding_label = QLabel()
            root.addWidget(self.binding_label)
            self.binding_combo = QComboBox()
            self.binding_combo.addItem("", "machine")
            self.binding_combo.addItem("", "none")
            self.binding_combo.currentIndexChanged.connect(self._on_binding_mode_changed)
            root.addWidget(self.binding_combo)

            self.fingerprints_box = QPlainTextEdit()
            self.fingerprints_box.textChanged.connect(self._on_fingerprints_changed)
            root.addWidget(self.fingerprints_box)

            binding_btn_row = QHBoxLayout()
            self.import_fp_btn = QPushButton()
            self.import_fp_btn.clicked.connect(self._on_import_fingerprints)
            binding_btn_row.addWidget(self.import_fp_btn)
            self.export_collector_btn = QPushButton()
            self.export_collector_btn.clicked.connect(self._on_export_collector)
            binding_btn_row.addWidget(self.export_collector_btn)
            binding_btn_row.addStretch()
            root.addLayout(binding_btn_row)

            self.fingerprint_count_label = QLabel()
            root.addWidget(self.fingerprint_count_label)

            self.gen_btn = QPushButton()
            self.gen_btn.clicked.connect(self._on_generate)
            root.addWidget(self.gen_btn)

            self._on_protocol_changed(self.protocol.currentText())
            self._add_mount_row()
            self._on_binding_mode_changed()
            self.retranslate()

        def _strings(self):
            return STRINGS[self.lang]

        def _on_lang_changed(self):
            self.lang = self.lang_combo.currentData()
            self.retranslate()

        def retranslate(self):
            s = self._strings()
            self.setWindowTitle(s["window_title"])
            self.lang_label.setText(s["language"])
            self.form.labelForField(self.protocol).setText(s["protocol"])
            self.form.labelForField(self.host).setText(s["host"])
            self.form.labelForField(self.username).setText(s["username"])
            self.form.labelForField(self.password).setText(s["password"])
            self.form.labelForField(self.domain).setText(s["domain"])
            self.form.labelForField(self.default_options).setText(s["default_options"])
            self.mounts_label.setText(s["mounts_label"])
            self.add_mount_btn.setText(s["add_mount"])
            self.form2.labelForField(self.retry_attempts).setText(s["retry_attempts"])
            self.form2.labelForField(self.retry_delay).setText(s["retry_delay"])
            self.install_deps.setText(s["install_deps"])
            self.form2.labelForField(self.out_path).setText(s["out_path"])
            self.form2.labelForField(self.save_config_path).setText(s["save_config"])
            self.save_config_path.setPlaceholderText(s["save_config_placeholder"])
            self.gen_btn.setText(s["generate"])
            for row in self.mount_rows:
                row.retranslate(s)
            self.binding_label.setText(s["binding_label"])
            self.binding_combo.setItemText(0, s["binding_machine"])
            self.binding_combo.setItemText(1, s["binding_none"])
            self.fingerprints_box.setPlaceholderText(s["binding_fingerprints_placeholder"])
            self.import_fp_btn.setText(s["binding_import_file"])
            self.export_collector_btn.setText(s["export_collector"])
            self._update_fingerprint_count_label()

        def _on_protocol_changed(self, protocol):
            if protocol == "cifs":
                self.default_options.setText(
                    "vers=3.0,iocharset=utf8,uid=0,gid=0,file_mode=0644,dir_mode=0755")
            else:
                self.default_options.setText("vers=4,soft,timeo=50,retrans=3")

        def _add_mount_row(self):
            row = MountRow(self._remove_mount_row, self._strings())
            self.mount_rows.append(row)
            self.mounts_box.addWidget(row)

        def _remove_mount_row(self, row):
            if len(self.mount_rows) <= 1:
                return
            self.mount_rows.remove(row)
            row.setParent(None)
            row.deleteLater()

        def _on_binding_mode_changed(self):
            is_machine = self.binding_combo.currentData() == "machine"
            self.fingerprints_box.setVisible(is_machine)
            self.import_fp_btn.setVisible(is_machine)
            self.fingerprint_count_label.setVisible(is_machine)

        def _parsed_fingerprints(self):
            return [line.strip() for line in self.fingerprints_box.toPlainText().splitlines() if line.strip()]

        def _update_fingerprint_count_label(self):
            s = self._strings()
            self.fingerprint_count_label.setText(s["binding_count"].format(n=len(self._parsed_fingerprints())))

        def _on_fingerprints_changed(self):
            self._update_fingerprint_count_label()

        def _on_import_fingerprints(self):
            path, _ = QFileDialog.getOpenFileName(self, self._strings()["binding_import_file"])
            if not path:
                return
            with open(path) as f:
                lines = [line.strip() for line in f if line.strip()]
            existing = self.fingerprints_box.toPlainText()
            combined = (existing + "\n" if existing.strip() else "") + "\n".join(lines)
            self.fingerprints_box.setPlainText(combined)

        def _on_export_collector(self):
            s = self._strings()
            path, _ = QFileDialog.getSaveFileName(self, s["export_collector"], "nas-enp-fingerprint.py")
            if not path:
                return
            emit_collector(path)
            QMessageBox.information(self, s["done_title"], s["export_collector_saved"].format(path=os.path.abspath(path)))

        def _collect_config(self):
            mounts = [r.to_dict() for r in self.mount_rows]
            mounts = [m for m in mounts if m["remote"] and m["local"]]
            mode = self.binding_combo.currentData()
            binding = {"mode": mode, "fingerprints": self._parsed_fingerprints() if mode == "machine" else []}
            return {
                "protocol": self.protocol.currentText(),
                "host": self.host.text().strip(),
                "username": self.username.text().strip(),
                "password": self.password.text(),
                "domain": self.domain.text().strip(),
                "default_options": self.default_options.text().strip(),
                "mounts": mounts,
                "retry_attempts": self.retry_attempts.value(),
                "retry_delay_sec": self.retry_delay.value(),
                "install_deps": self.install_deps.isChecked(),
                "binding": binding,
            }

        def _on_generate(self):
            s = self._strings()
            cfg = self._collect_config()
            try:
                validate(cfg)
            except SystemExit as e:
                QMessageBox.critical(self, s["invalid_config_title"],
                                      translate_validation_msg(str(e), self.lang))
                return

            out_path = self.out_path.text().strip() or "nas-enp-mount.py"
            save_path = self.save_config_path.text().strip()
            if save_path:
                with open(save_path, "w") as f:
                    json.dump(cfg, f, indent=2)
                os.chmod(save_path, 0o600)

            src = fill_template(cfg)
            out_abs = os.path.abspath(out_path)
            with open(out_abs, "w", newline="\n") as f:
                f.write(src)
            os.chmod(out_abs, 0o700)
            try:
                self_check_no_leak(src, cfg, out_abs)
            except SystemExit as e:
                QMessageBox.critical(self, s["invalid_config_title"], str(e))
                return

            dlg = QDialog(self)
            dlg.setWindowTitle(s["done_title"])
            layout = QVBoxLayout(dlg)
            text = QPlainTextEdit(
                s["script_written"].format(path=out_abs) + deploy_instructions(out_abs, lang=self.lang))
            text.setReadOnly(True)
            layout.addWidget(text)
            close_btn = QPushButton(s["close"])
            close_btn.clicked.connect(dlg.accept)
            layout.addWidget(close_btn)
            dlg.resize(600, 400)
            dlg.exec()

    app = QApplication.instance() or QApplication(sys.argv)
    win = GeneratorWindow()
    win.resize(700, 550)
    win.show()
    app.exec()

# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="Generate an encrypted NAS auto-mount client script.")
    ap.add_argument("--config", help="JSON config file (skips interactive prompts / GUI)")
    ap.add_argument("--cli", action="store_true", help="use terminal prompts instead of the GUI")
    ap.add_argument("--out", default="nas-enp-mount.py", help="output client script path")
    ap.add_argument("--save-config", help="write the collected config to this JSON file (contains the PASSWORD in cleartext, guard it)")
    ap.add_argument("--emit-collector", action="store_true",
                     help="write a standalone fingerprint-collection script for a target machine and exit")
    args = ap.parse_args()

    if args.emit_collector:
        emit_collector(args.out if args.out != "nas-enp-mount.py" else "nas-enp-fingerprint.py")
        return

    if args.config:
        with open(args.config) as f:
            cfg = json.load(f)
        validate(cfg)
    elif args.cli:
        cfg = prompt_config()
        validate(cfg)
    else:
        launch_gui()
        return

    if args.save_config:
        with open(args.save_config, "w") as f:
            json.dump(cfg, f, indent=2)
        os.chmod(args.save_config, 0o600)
        print(f"[note] config saved to {args.save_config} (0600). It holds the cleartext password.")

    src = fill_template(cfg)
    out_abs = os.path.abspath(args.out)
    with open(out_abs, "w", newline="\n") as f:
        f.write(src)
    os.chmod(out_abs, 0o700)
    self_check_no_leak(src, cfg, out_abs)

    print(f"\n[emit] Client script written to: {out_abs}")
    print(deploy_instructions(out_abs))

if __name__ == "__main__":
    main()
