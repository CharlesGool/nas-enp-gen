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

Usage:
  python3 nas-enp-gen.py                       # launch the GUI
  python3 nas-enp-gen.py --cli                  # interactive terminal prompts
  python3 nas-enp-gen.py --config nas.json      # from a JSON file, headless
  python3 nas-enp-gen.py --config nas.json --out nas-enp-mount.py
"""
import argparse, base64, getpass, json, os, subprocess, sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Missing dependency. Run:  pip install cryptography")

# ---- Embedded Python client template (base64) ----
PY_CLIENT_TEMPLATE_B64 = (
    "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiIKbmFzLWVucC1tb3VudCBjbGllbnQKQnVpbHQgZnJvbSBhbiBlbmNyeXB0"
    "ZWQgY29uZmlnIGJsb2IgZW1iZWRkZWQgYXQgZ2VuZXJhdGlvbiB0aW1lLgpUaGUgcGxhaW50ZXh0IGNvbmZpZyBuZXZl"
    "ciB0b3VjaGVzIGRpc2sgb24gdGhlIGNsaWVudC4KIiIiCmltcG9ydCBiYXNlNjQKaW1wb3J0IGpzb24KaW1wb3J0IG9z"
    "CmltcG9ydCBzdWJwcm9jZXNzCmltcG9ydCBzeXMKaW1wb3J0IHRpbWUKZnJvbSBzaHV0aWwgaW1wb3J0IHdoaWNoCgpJ"
    "TlNUQUxMX0RJUiA9ICIvcm9vdC9uYXMtZW5wLW1vdW50IgpCSU5fTkFNRSA9ICJuYXMtZW5wLW1vdW50LnB5IgpTRVJW"
    "SUNFX05BTUUgPSAibmFzLWVucC1tb3VudC5zZXJ2aWNlIgoKIyAtLS0tIEVtYmVkZGVkIGJsb2IgKGZpbGxlZCBpbiBi"
    "eSB0aGUgZ2VuZXJhdG9yKSAtLS0tCkJMT0JfQ0lQSEVSID0gIl9fQ0lQSEVSVEVYVF9fIgpCTE9CX05PTkNFID0gIl9f"
    "Tk9OQ0VfXyIKQkxPQl9LRVlBID0gIl9fS0VZQV9fIgpCTE9CX0tFWVBBRCA9ICJfX0tFWVBBRF9fIgoKCmRlZiBsb2dm"
    "KG1zZyk6CiAgICBwcmludChmIltuYXMtZW5wLW1vdW50XSB7bXNnfSIsIGZpbGU9c3lzLnN0ZGVycikKCgpkZWYgX3Bp"
    "cF9pbnN0YWxsKHBrZyk6CiAgICByID0gc3VicHJvY2Vzcy5ydW4oW3N5cy5leGVjdXRhYmxlLCAiLW0iLCAicGlwIiwg"
    "Imluc3RhbGwiLCAiLS1xdWlldCIsIHBrZ10sCiAgICAgICAgICAgICAgICAgICAgICAgIGNhcHR1cmVfb3V0cHV0PVRy"
    "dWUsIHRleHQ9VHJ1ZSkKICAgIGlmIHIucmV0dXJuY29kZSAhPSAwOgogICAgICAgICMgcGlwIG1vZHVsZSBtYXkgYmUg"
    "bWlzc2luZyBlbnRpcmVseSBvbiBhIG1pbmltYWwgaW1hZ2U7IGJvb3RzdHJhcCBpdCBvbmNlLgogICAgICAgIHN1YnBy"
    "b2Nlc3MucnVuKFtzeXMuZXhlY3V0YWJsZSwgIi1tIiwgImVuc3VyZXBpcCIsICItLWRlZmF1bHQtcGlwIl0sCiAgICAg"
    "ICAgICAgICAgICAgICAgICAgIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRleHQ9VHJ1ZSkKICAgICAgICByID0gc3VicHJv"
    "Y2Vzcy5ydW4oW3N5cy5leGVjdXRhYmxlLCAiLW0iLCAicGlwIiwgImluc3RhbGwiLCAiLS1xdWlldCIsIHBrZ10sCiAg"
    "ICAgICAgICAgICAgICAgICAgICAgICAgICBjYXB0dXJlX291dHB1dD1UcnVlLCB0ZXh0PVRydWUpCiAgICByZXR1cm4g"
    "cgoKCmRlZiBlbnN1cmVfY3J5cHRvKCk6CiAgICB0cnk6CiAgICAgICAgZnJvbSBjcnlwdG9ncmFwaHkuaGF6bWF0LnBy"
    "aW1pdGl2ZXMuY2lwaGVycy5hZWFkIGltcG9ydCBBRVNHQ00KICAgICAgICByZXR1cm4gQUVTR0NNCiAgICBleGNlcHQg"
    "SW1wb3J0RXJyb3I6CiAgICAgICAgbG9nZigiY3J5cHRvZ3JhcGh5IHBhY2thZ2UgbWlzc2luZzsgaW5zdGFsbGluZyB2"
    "aWEgcGlwIC4uLiIpCiAgICAgICAgciA9IF9waXBfaW5zdGFsbCgiY3J5cHRvZ3JhcGh5IikKICAgICAgICBpZiByLnJl"
    "dHVybmNvZGUgIT0gMDoKICAgICAgICAgICAgbG9nZihmImZhdGFsOiBwaXAgaW5zdGFsbCBjcnlwdG9ncmFwaHkgZmFp"
    "bGVkOlxue3Iuc3Rkb3V0fXtyLnN0ZGVycn0iKQogICAgICAgICAgICBzeXMuZXhpdCgyKQogICAgICAgIHRyeToKICAg"
    "ICAgICAgICAgZnJvbSBjcnlwdG9ncmFwaHkuaGF6bWF0LnByaW1pdGl2ZXMuY2lwaGVycy5hZWFkIGltcG9ydCBBRVNH"
    "Q00KICAgICAgICAgICAgcmV0dXJuIEFFU0dDTQogICAgICAgIGV4Y2VwdCBJbXBvcnRFcnJvcjoKICAgICAgICAgICAg"
    "bG9nZigiZmF0YWw6IGNyeXB0b2dyYXBoeSBzdGlsbCBub3QgaW1wb3J0YWJsZSBhZnRlciBpbnN0YWxsIikKICAgICAg"
    "ICAgICAgc3lzLmV4aXQoMikKCgpBRVNHQ00gPSBlbnN1cmVfY3J5cHRvKCkKCgpkZWYgZGVjb2RlX2I2NChzKToKICAg"
    "IHRyeToKICAgICAgICByZXR1cm4gYmFzZTY0LmI2NGRlY29kZShzKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgog"
    "ICAgICAgIGxvZ2YoZiJmYXRhbDogYmxvYiBkZWNvZGUgZXJyb3I6IHtlfSIpCiAgICAgICAgc3lzLmV4aXQoMikKCgpk"
    "ZWYgbG9hZF9jb25maWcoKToKICAgIGtleV9hID0gZGVjb2RlX2I2NChCTE9CX0tFWUEpCiAgICBrZXlfcGFkID0gZGVj"
    "b2RlX2I2NChCTE9CX0tFWVBBRCkKICAgIGlmIGxlbihrZXlfYSkgIT0gbGVuKGtleV9wYWQpOgogICAgICAgIHJhaXNl"
    "IFJ1bnRpbWVFcnJvcigia2V5IG1hdGVyaWFsIGxlbmd0aCBtaXNtYXRjaCIpCiAgICBrZXkgPSBieXRlYXJyYXkoYSBe"
    "IGIgZm9yIGEsIGIgaW4gemlwKGtleV9hLCBrZXlfcGFkKSkKICAgIHRyeToKICAgICAgICBwbGFpbiA9IEFFU0dDTShi"
    "eXRlcyhrZXkpKS5kZWNyeXB0KGRlY29kZV9iNjQoQkxPQl9OT05DRSksIGRlY29kZV9iNjQoQkxPQl9DSVBIRVIpLCBO"
    "b25lKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcihmImNvbmZpZyBh"
    "dXRoL2RlY3J5cHQgZmFpbGVkOiB7ZX0iKQogICAgZmluYWxseToKICAgICAgICAjIGJlc3QtZWZmb3J0IHplcm9pbmcg"
    "b2YgdGhlIG11dGFibGUgY29weTsgdGhlIGJ5dGVzKCkgY29weSBwYXNzZWQgdG8KICAgICAgICAjIEFFU0dDTSBhYm92"
    "ZSBpcyBpbW11dGFibGUgYW5kIGNhbid0IGJlIHplcm9lZCB0aGUgc2FtZSB3YXkKICAgICAgICBmb3IgaSBpbiByYW5n"
    "ZShsZW4oa2V5KSk6CiAgICAgICAgICAgIGtleVtpXSA9IDAKICAgIHJldHVybiBqc29uLmxvYWRzKHBsYWluKQoKCmRl"
    "ZiByZXF1aXJlX3Jvb3QoKToKICAgIGlmIG9zLmdldGV1aWQoKSAhPSAwOgogICAgICAgIGxvZ2YoImZhdGFsOiBtdXN0"
    "IGJlIHJ1biBhcyByb290IikKICAgICAgICBzeXMuZXhpdCgxKQoKCmRlZiBpc19tb3VudGVkKHRhcmdldCk6CiAgICB0"
    "cnk6CiAgICAgICAgd2l0aCBvcGVuKCIvcHJvYy9tb3VudHMiKSBhcyBmOgogICAgICAgICAgICBkYXRhID0gZi5yZWFk"
    "KCkKICAgIGV4Y2VwdCBPU0Vycm9yOgogICAgICAgIHJldHVybiBGYWxzZQogICAgYWJzX3RhcmdldCA9IG9zLnBhdGgu"
    "YWJzcGF0aCh0YXJnZXQpCiAgICBmb3IgbGluZSBpbiBkYXRhLnNwbGl0bGluZXMoKToKICAgICAgICBmaWVsZHMgPSBs"
    "aW5lLnNwbGl0KCkKICAgICAgICBpZiBsZW4oZmllbGRzKSA+PSAyIGFuZCBmaWVsZHNbMV0gaW4gKGFic190YXJnZXQs"
    "IHRhcmdldCk6CiAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICByZXR1cm4gRmFsc2UKCgpkZWYgaGF2ZV9jbWQobmFt"
    "ZSk6CiAgICByZXR1cm4gd2hpY2gobmFtZSkgaXMgbm90IE5vbmUKCgpkZWYgZW5zdXJlX2RlcHMoY2ZnKToKICAgIGlm"
    "IGNmZ1sicHJvdG9jb2wiXSA9PSAiY2lmcyIgYW5kIG5vdCBoYXZlX2NtZCgibW91bnQuY2lmcyIpOgogICAgICAgIGlm"
    "IGNmZy5nZXQoImluc3RhbGxfZGVwcyIpIGFuZCBoYXZlX2NtZCgiYXB0LWdldCIpOgogICAgICAgICAgICBsb2dmKCJt"
    "b3VudC5jaWZzIG1pc3Npbmc7IGluc3RhbGxpbmcgY2lmcy11dGlscyAuLi4iKQogICAgICAgICAgICBlbnYgPSBkaWN0"
    "KG9zLmVudmlyb24sIERFQklBTl9GUk9OVEVORD0ibm9uaW50ZXJhY3RpdmUiKQogICAgICAgICAgICByID0gc3VicHJv"
    "Y2Vzcy5ydW4oWyJhcHQtZ2V0IiwgImluc3RhbGwiLCAiLXkiLCAiY2lmcy11dGlscyJdLAogICAgICAgICAgICAgICAg"
    "ICAgICAgICAgICAgICAgIGVudj1lbnYsIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRleHQ9VHJ1ZSkKICAgICAgICAgICAg"
    "aWYgci5yZXR1cm5jb2RlICE9IDA6CiAgICAgICAgICAgICAgICBsb2dmKGYid2FybjogY2lmcy11dGlscyBpbnN0YWxs"
    "IGZhaWxlZDoge3IucmV0dXJuY29kZX1cbntyLnN0ZG91dH17ci5zdGRlcnJ9IikKICAgICAgICBlbHNlOgogICAgICAg"
    "ICAgICBsb2dmKCJ3YXJuOiBtb3VudC5jaWZzIG5vdCBmb3VuZDsgaW5zdGFsbCBjaWZzLXV0aWxzIChhcHQtZ2V0IGlu"
    "c3RhbGwgY2lmcy11dGlscykiKQoKCmRlZiBidWlsZF9zb3VyY2UoY2ZnLCBtKToKICAgIGlmIGNmZ1sicHJvdG9jb2wi"
    "XSA9PSAibmZzIjoKICAgICAgICByZXR1cm4gZid7Y2ZnWyJob3N0Il19OnttWyJyZW1vdGUiXX0nCiAgICByZW0gPSBt"
    "WyJyZW1vdGUiXS5sc3RyaXAoIi8iKQogICAgcmV0dXJuIGYnLy97Y2ZnWyJob3N0Il19L3tyZW19JwoKCmRlZiBtb3Vu"
    "dF9vbmUoY2ZnLCBtLCBpZHgpOgogICAgaWYgaXNfbW91bnRlZChtWyJsb2NhbCJdKToKICAgICAgICBsb2dmKGYibW91"
    "bnQgI3tpZHh9OiBhbHJlYWR5IG1vdW50ZWQiKQogICAgICAgIHJldHVybiBUcnVlCiAgICB0cnk6CiAgICAgICAgb3Mu"
    "bWFrZWRpcnMobVsibG9jYWwiXSwgbW9kZT0wbzc1NSwgZXhpc3Rfb2s9VHJ1ZSkKICAgIGV4Y2VwdCBPU0Vycm9yOgog"
    "ICAgICAgIGxvZ2YoZiJtb3VudCAje2lkeH06IG1rZGlyIGZhaWxlZCIpCiAgICAgICAgcmV0dXJuIEZhbHNlCgogICAg"
    "b3B0cyA9IGNmZy5nZXQoImRlZmF1bHRfb3B0aW9ucyIsICIiKQogICAgaWYgbS5nZXQoIm9wdGlvbnMiLCAiIikuc3Ry"
    "aXAoKToKICAgICAgICBvcHRzID0gbVsib3B0aW9ucyJdCgogICAgc3JjID0gYnVpbGRfc291cmNlKGNmZywgbSkKICAg"
    "IGlmIGNmZ1sicHJvdG9jb2wiXSA9PSAiY2lmcyI6CiAgICAgICAgcGFydHMgPSBbXQogICAgICAgIGlmIG9wdHM6CiAg"
    "ICAgICAgICAgIHBhcnRzLmFwcGVuZChvcHRzKQogICAgICAgIHBhcnRzLmFwcGVuZCgidXNlcm5hbWU9IiArIGNmZ1si"
    "dXNlcm5hbWUiXSkKICAgICAgICBpZiBjZmcuZ2V0KCJkb21haW4iKToKICAgICAgICAgICAgcGFydHMuYXBwZW5kKCJk"
    "b21haW49IiArIGNmZ1siZG9tYWluIl0pCiAgICAgICAgZnVsbCA9ICIsIi5qb2luKHBhcnRzKQogICAgICAgIGVudiA9"
    "IGRpY3Qob3MuZW52aXJvbiwgUEFTU1dEPWNmZy5nZXQoInBhc3N3b3JkIiwgIiIpKQogICAgICAgIGNtZCA9IFsibW91"
    "bnQuY2lmcyIsIHNyYywgbVsibG9jYWwiXSwgIi1vIiwgZnVsbF0KICAgIGVsc2U6CiAgICAgICAgYXJncyA9IFsiLXQi"
    "LCAibmZzIl0KICAgICAgICBpZiBvcHRzOgogICAgICAgICAgICBhcmdzICs9IFsiLW8iLCBvcHRzXQogICAgICAgIGFy"
    "Z3MgKz0gW3NyYywgbVsibG9jYWwiXV0KICAgICAgICBjbWQgPSBbIm1vdW50Il0gKyBhcmdzCiAgICAgICAgZW52ID0g"
    "b3MuZW52aXJvbi5jb3B5KCkKCiAgICAjIERlbGliZXJhdGVseSBkb24ndCBsb2cgY21kL3NyYy9tWyJsb2NhbCJdIG9y"
    "IHRoZSBzdWJwcm9jZXNzJ3Mgb3duCiAgICAjIHN0ZG91dC9zdGRlcnI6IG1vdW50IHRvb2wgZXJyb3IgdGV4dCBjYW4g"
    "aXRzZWxmIGVtYmVkIHRoZSBOQVMgaG9zdAogICAgIyBvciBzaGFyZSBwYXRoLCBhbmQgdGhpcyBwcm9qZWN0J3MgcG9s"
    "aWN5IGlzIHRvIG5ldmVyIHN1cmZhY2UgTkFTCiAgICAjIGlkZW50aWZ5aW5nIGRldGFpbHMgaW4gbG9ncyAoam91cm5h"
    "bGN0bCBldGMuKSDigJQgb25seSBzdWNjZXNzL2ZhaWx1cmUuCiAgICByID0gc3VicHJvY2Vzcy5ydW4oY21kLCBlbnY9"
    "ZW52LCBjYXB0dXJlX291dHB1dD1UcnVlLCB0ZXh0PVRydWUpCiAgICBpZiByLnJldHVybmNvZGUgIT0gMDoKICAgICAg"
    "ICBsb2dmKGYibW91bnQgI3tpZHh9OiBmYWlsZWQgKGV4aXQgY29kZSB7ci5yZXR1cm5jb2RlfSkiKQogICAgICAgIHJl"
    "dHVybiBGYWxzZQogICAgbG9nZihmIm1vdW50ICN7aWR4fTogbW91bnRlZCIpCiAgICByZXR1cm4gVHJ1ZQoKCmRlZiBv"
    "bmVzaG90KCk6CiAgICByZXF1aXJlX3Jvb3QoKQogICAgdHJ5OgogICAgICAgIGNmZyA9IGxvYWRfY29uZmlnKCkKICAg"
    "IGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBsb2dmKGYiZmF0YWw6IHtlfSIpCiAgICAgICAgcmV0dXJuIDIK"
    "ICAgIGVuc3VyZV9kZXBzKGNmZykKCiAgICBhdHRlbXB0cyA9IGNmZy5nZXQoInJldHJ5X2F0dGVtcHRzIikgb3IgMQog"
    "ICAgaWYgYXR0ZW1wdHMgPCAxOgogICAgICAgIGF0dGVtcHRzID0gMQogICAgZGVsYXkgPSBjZmcuZ2V0KCJyZXRyeV9k"
    "ZWxheV9zZWMiKSBvciA1CiAgICBpZiBkZWxheSA8PSAwOgogICAgICAgIGRlbGF5ID0gNQoKICAgIHRvdGFsID0gbGVu"
    "KGNmZ1sibW91bnRzIl0pCiAgICBwZW5kaW5nID0gbGlzdChlbnVtZXJhdGUoY2ZnWyJtb3VudHMiXSwgc3RhcnQ9MSkp"
    "CiAgICBhdHRlbXB0ID0gMQogICAgd2hpbGUgYXR0ZW1wdCA8PSBhdHRlbXB0cyBhbmQgcGVuZGluZzoKICAgICAgICBz"
    "dGlsbF9wZW5kaW5nID0gW10KICAgICAgICBmb3IgaWR4LCBtIGluIHBlbmRpbmc6CiAgICAgICAgICAgIGlmIG5vdCBt"
    "b3VudF9vbmUoY2ZnLCBtLCBpZHgpOgogICAgICAgICAgICAgICAgc3RpbGxfcGVuZGluZy5hcHBlbmQoKGlkeCwgbSkp"
    "CiAgICAgICAgcGVuZGluZyA9IHN0aWxsX3BlbmRpbmcKICAgICAgICBpZiBwZW5kaW5nIGFuZCBhdHRlbXB0IDwgYXR0"
    "ZW1wdHM6CiAgICAgICAgICAgIGQgPSBtaW4oZGVsYXkgKiBhdHRlbXB0LCA2MCkKICAgICAgICAgICAgbG9nZihmInts"
    "ZW4ocGVuZGluZyl9L3t0b3RhbH0gbW91bnQocykgcGVuZGluZywgcmV0cnlpbmcgaW4ge2R9cyAuLi4iKQogICAgICAg"
    "ICAgICB0aW1lLnNsZWVwKGQpCiAgICAgICAgYXR0ZW1wdCArPSAxCgogICAgaWYgcGVuZGluZzoKICAgICAgICBsb2dm"
    "KGYiZ2l2aW5nIHVwOiB7bGVuKHBlbmRpbmcpfS97dG90YWx9IG1vdW50KHMpIG5vdCBtb3VudGVkIikKICAgICAgICBy"
    "ZXR1cm4gMSAgIyBub256ZXJvLCBidXQgYm9vdCBpcyB1bmFmZmVjdGVkIGJlY2F1c2Ugbm90aGluZyBkZXBlbmRzIG9u"
    "IHRoaXMgdW5pdAogICAgbG9nZihmImFsbCB7dG90YWx9IG1vdW50KHMpIHVwIikKICAgIHJldHVybiAwCgoKZGVmIHN0"
    "YXR1cygpOgogICAgdHJ5OgogICAgICAgIGNmZyA9IGxvYWRfY29uZmlnKCkKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMg"
    "ZToKICAgICAgICBsb2dmKGYiZmF0YWw6IHtlfSIpCiAgICAgICAgcmV0dXJuIDIKICAgIHRvdGFsID0gbGVuKGNmZ1si"
    "bW91bnRzIl0pCiAgICBtb3VudGVkID0gc3VtKDEgZm9yIG0gaW4gY2ZnWyJtb3VudHMiXSBpZiBpc19tb3VudGVkKG1b"
    "ImxvY2FsIl0pKQogICAgcHJpbnQoZiJ7bW91bnRlZH0ve3RvdGFsfSBtb3VudChzKSBhY3RpdmUiKQogICAgcmV0dXJu"
    "IDAKCgpkZWYgc2VsZnRlc3QoKToKICAgIHRyeToKICAgICAgICBjZmcgPSBsb2FkX2NvbmZpZygpCiAgICBleGNlcHQg"
    "RXhjZXB0aW9uIGFzIGU6CiAgICAgICAgbG9nZihmInNlbGZ0ZXN0IEZBSUxFRDoge2V9IikKICAgICAgICByZXR1cm4g"
    "MgogICAgcHJpbnQoZidjb25maWcgZGVjcnlwdGVkIE9LOiBwcm90b2NvbD17Y2ZnWyJwcm90b2NvbCJdfSBtb3VudHM9"
    "e2xlbihjZmdbIm1vdW50cyJdKX0nKQogICAgcmV0dXJuIDAKCgpVTklUX1RFTVBMQVRFID0gIiIiW1VuaXRdCkRlc2Ny"
    "aXB0aW9uPU5BUyBhdXRvIG1vdW50IChuYXMtZW5wLW1vdW50KQpBZnRlcj1uZXR3b3JrLW9ubGluZS50YXJnZXQKV2Fu"
    "dHM9bmV0d29yay1vbmxpbmUudGFyZ2V0CiMgSW50ZW50aW9uYWxseSBubyBSZXF1aXJlcyBmcm9tIG90aGVyIHVuaXRz"
    "IC0+IGZhaWx1cmVzIG5ldmVyIGJsb2NrIGJvb3QuClN0YXJ0TGltaXRJbnRlcnZhbFNlYz0wCgpbU2VydmljZV0KVHlw"
    "ZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKRXhlY1N0YXJ0PXtweXRob259IHtzY3JpcHR9IC0tb25lc2hvdAoj"
    "IEJvdW5kZWQgc28gYSBkZWFkIE5BUyBjYW4gbmV2ZXIgaGFuZyBib290OyByZXRyaWVzIGhhcHBlbiBpbnNpZGUgdGhp"
    "cyBidWRnZXQuClRpbWVvdXRTdGFydFNlYz0xNTAKCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAoi"
    "IiIKCgpkZWYgaW5zdGFsbF9zZXJ2aWNlKCk6CiAgICByZXF1aXJlX3Jvb3QoKQogICAgdHJ5OgogICAgICAgIGxvYWRf"
    "Y29uZmlnKCkKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBsb2dmKGYicmVmdXNpbmcgdG8gaW5zdGFs"
    "bDoge2V9IikKICAgICAgICByZXR1cm4gMgogICAgb3MubWFrZWRpcnMoSU5TVEFMTF9ESVIsIG1vZGU9MG83MDAsIGV4"
    "aXN0X29rPVRydWUpCiAgICB0YXJnZXQgPSBvcy5wYXRoLmpvaW4oSU5TVEFMTF9ESVIsIEJJTl9OQU1FKQogICAgc2Vs"
    "Zl9wYXRoID0gb3MucGF0aC5hYnNwYXRoKF9fZmlsZV9fKQogICAgaWYgc2VsZl9wYXRoICE9IHRhcmdldDoKICAgICAg"
    "ICB3aXRoIG9wZW4oc2VsZl9wYXRoLCAicmIiKSBhcyBmOgogICAgICAgICAgICBkYXRhID0gZi5yZWFkKCkKICAgICAg"
    "ICB3aXRoIG9wZW4odGFyZ2V0LCAid2IiKSBhcyBmOgogICAgICAgICAgICBmLndyaXRlKGRhdGEpCiAgICAgICAgb3Mu"
    "Y2htb2QodGFyZ2V0LCAwbzcwMCkKICAgICAgICBsb2dmKGYiaW5zdGFsbGVkIHNjcmlwdCB0byB7dGFyZ2V0fSIpCgog"
    "ICAgdW5pdCA9IFVOSVRfVEVNUExBVEUuZm9ybWF0KHB5dGhvbj1zeXMuZXhlY3V0YWJsZSwgc2NyaXB0PXRhcmdldCkK"
    "ICAgIHVuaXRfcGF0aCA9IGYiL2V0Yy9zeXN0ZW1kL3N5c3RlbS97U0VSVklDRV9OQU1FfSIKICAgIHdpdGggb3Blbih1"
    "bml0X3BhdGgsICJ3IikgYXMgZjoKICAgICAgICBmLndyaXRlKHVuaXQpCiAgICBsb2dmKGYid3JvdGUge3VuaXRfcGF0"
    "aH0iKQogICAgZm9yIGFyZ3MgaW4gKFsiZGFlbW9uLXJlbG9hZCJdLCBbImVuYWJsZSIsIFNFUlZJQ0VfTkFNRV0sIFsi"
    "c3RhcnQiLCBTRVJWSUNFX05BTUVdKToKICAgICAgICByID0gc3VicHJvY2Vzcy5ydW4oWyJzeXN0ZW1jdGwiXSArIGFy"
    "Z3MsIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRleHQ9VHJ1ZSkKICAgICAgICBpZiByLnJldHVybmNvZGUgIT0gMDoKICAg"
    "ICAgICAgICAgbG9nZihmIndhcm46IHN5c3RlbWN0bCB7YXJnc306IHtyLnJldHVybmNvZGV9OiB7KHIuc3Rkb3V0ICsg"
    "ci5zdGRlcnIpLnN0cmlwKCl9IikKICAgIGxvZ2YoZiJzZXJ2aWNlIGluc3RhbGxlZCBhbmQgc3RhcnRlZC4gQ2hlY2s6"
    "IHN5c3RlbWN0bCBzdGF0dXMge1NFUlZJQ0VfTkFNRX0iKQogICAgcmV0dXJuIDAKCgpkZWYgdW5pbnN0YWxsKCk6CiAg"
    "ICByZXF1aXJlX3Jvb3QoKQogICAgc3VicHJvY2Vzcy5ydW4oWyJzeXN0ZW1jdGwiLCAiZGlzYWJsZSIsICItLW5vdyIs"
    "IFNFUlZJQ0VfTkFNRV0sIGNhcHR1cmVfb3V0cHV0PVRydWUpCiAgICB0cnk6CiAgICAgICAgb3MucmVtb3ZlKGYiL2V0"
    "Yy9zeXN0ZW1kL3N5c3RlbS97U0VSVklDRV9OQU1FfSIpCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICBwYXNzCiAg"
    "ICBzdWJwcm9jZXNzLnJ1bihbInN5c3RlbWN0bCIsICJkYWVtb24tcmVsb2FkIl0sIGNhcHR1cmVfb3V0cHV0PVRydWUp"
    "CiAgICB0cnk6CiAgICAgICAgY2ZnID0gbG9hZF9jb25maWcoKQogICAgICAgIHVubW91bnRlZCA9IDAKICAgICAgICBm"
    "b3IgbSBpbiBjZmdbIm1vdW50cyJdOgogICAgICAgICAgICBpZiBpc19tb3VudGVkKG1bImxvY2FsIl0pOgogICAgICAg"
    "ICAgICAgICAgciA9IHN1YnByb2Nlc3MucnVuKFsidW1vdW50IiwgbVsibG9jYWwiXV0sIGNhcHR1cmVfb3V0cHV0PVRy"
    "dWUsIHRleHQ9VHJ1ZSkKICAgICAgICAgICAgICAgIGlmIHIucmV0dXJuY29kZSA9PSAwOgogICAgICAgICAgICAgICAg"
    "ICAgIHVubW91bnRlZCArPSAxCiAgICAgICAgbG9nZihmInVubW91bnRlZCB7dW5tb3VudGVkfSBzaGFyZShzKSIpCiAg"
    "ICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIHBhc3MKICAgIGxvZ2YoInVuaW5zdGFsbGVkIikKICAgIHJldHVybiAw"
    "CgoKZGVmIHVzYWdlKCk6CiAgICBwcmludCgiIiJuYXMtZW5wLW1vdW50CiAgKG5vIGFyZ3MpIC8gLS1vbmVzaG90ICAg"
    "bW91bnQgYWxsIHNoYXJlcyBvbmNlICh3aXRoIGludGVybmFsIHJldHJpZXMpCiAgLS1pbnN0YWxsLXNlcnZpY2UgICAg"
    "ICAgaW5zdGFsbCAmIGVuYWJsZSBzeXN0ZW1kIGJvb3Qgc2VydmljZQogIC0tdW5pbnN0YWxsICAgICAgICAgICAgIHN0"
    "b3Agc2VydmljZSwgcmVtb3ZlIHVuaXQsIHVubW91bnQgc2hhcmVzCiAgLS1zdGF0dXMgICAgICAgICAgICAgICAgc2hv"
    "dyBtb3VudCBzdGF0dXMKICAtLXNlbGZ0ZXN0ICAgICAgICAgICAgICB2ZXJpZnkgZW1iZWRkZWQgY29uZmlnIGRlY3J5"
    "cHRzIChubyBzZWNyZXRzIHByaW50ZWQpIiIiKQoKCmRlZiBtYWluKCk6CiAgICBtb2RlID0gc3lzLmFyZ3ZbMV0gaWYg"
    "bGVuKHN5cy5hcmd2KSA+IDEgZWxzZSAiLS1vbmVzaG90IgogICAgaWYgbW9kZSBpbiAoIi0tb25lc2hvdCIsICIiKToK"
    "ICAgICAgICBzeXMuZXhpdChvbmVzaG90KCkpCiAgICBlbGlmIG1vZGUgPT0gIi0taW5zdGFsbC1zZXJ2aWNlIjoKICAg"
    "ICAgICBzeXMuZXhpdChpbnN0YWxsX3NlcnZpY2UoKSkKICAgIGVsaWYgbW9kZSA9PSAiLS11bmluc3RhbGwiOgogICAg"
    "ICAgIHN5cy5leGl0KHVuaW5zdGFsbCgpKQogICAgZWxpZiBtb2RlID09ICItLXN0YXR1cyI6CiAgICAgICAgc3lzLmV4"
    "aXQoc3RhdHVzKCkpCiAgICBlbGlmIG1vZGUgPT0gIi0tc2VsZnRlc3QiOgogICAgICAgIHN5cy5leGl0KHNlbGZ0ZXN0"
    "KCkpCiAgICBlbGlmIG1vZGUgaW4gKCItaCIsICItLWhlbHAiLCAiaGVscCIpOgogICAgICAgIHVzYWdlKCkKICAgIGVs"
    "c2U6CiAgICAgICAgdXNhZ2UoKQogICAgICAgIHN5cy5leGl0KDIpCgoKaWYgX19uYW1lX18gPT0gIl9fbWFpbl9fIjoK"
    "ICAgIG1haW4oKQo="
)

def py_client_template() -> str:
    return base64.b64decode("".join(PY_CLIENT_TEMPLATE_B64)).decode()

# ------------------------------------------------------------------ collect
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

    return {
        "protocol": protocol, "host": host, "username": username,
        "password": password, "domain": domain,
        "default_options": default_options, "mounts": mounts,
        "retry_attempts": retry_attempts, "retry_delay_sec": retry_delay,
        "install_deps": install_deps,
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

# ------------------------------------------------------------------ crypto
def encrypt_config(cfg: dict) -> dict:
    plain = json.dumps(cfg, separators=(",", ":")).encode()
    key = os.urandom(32)
    pad = os.urandom(32)
    key_a = bytes(a ^ b for a, b in zip(key, pad))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plain, None)
    b = lambda x: base64.b64encode(x).decode()
    return {"cipher": b(ct), "nonce": b(nonce), "keya": b(key_a), "keypad": b(pad)}

def fill_template(blob: dict) -> str:
    return (py_client_template()
            .replace("__CIPHERTEXT__", blob["cipher"])
            .replace("__NONCE__", blob["nonce"])
            .replace("__KEYA__", blob["keya"])
            .replace("__KEYPAD__", blob["keypad"]))

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
        QPlainTextEdit, QDialog,
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

            self.gen_btn = QPushButton()
            self.gen_btn.clicked.connect(self._on_generate)
            root.addWidget(self.gen_btn)

            self._on_protocol_changed(self.protocol.currentText())
            self._add_mount_row()
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

        def _collect_config(self):
            mounts = [r.to_dict() for r in self.mount_rows]
            mounts = [m for m in mounts if m["remote"] and m["local"]]
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

            blob = encrypt_config(cfg)
            src = fill_template(blob)
            out_abs = os.path.abspath(out_path)
            with open(out_abs, "w", newline="\n") as f:
                f.write(src)
            os.chmod(out_abs, 0o700)

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
    args = ap.parse_args()

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

    blob = encrypt_config(cfg)
    src = fill_template(blob)
    out_abs = os.path.abspath(args.out)
    with open(out_abs, "w", newline="\n") as f:
        f.write(src)
    os.chmod(out_abs, 0o700)

    print(f"\n[emit] Client script written to: {out_abs}")
    print(deploy_instructions(out_abs))

if __name__ == "__main__":
    main()
