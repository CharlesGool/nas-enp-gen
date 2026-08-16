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
    "IyEvdXNyL2Jpbi9lbnYgcHl0aG9uMwoiIiIKbmFzLWVucC1tb3VudCBjbGllbnQKQnVpbHQgZnJvbSBhbiBlbmNyeXB0ZWQgY29u"
    "ZmlnIGJsb2IgZW1iZWRkZWQgYXQgZ2VuZXJhdGlvbiB0aW1lLgpUaGUgcGxhaW50ZXh0IGNvbmZpZyBuZXZlciB0b3VjaGVzIGRp"
    "c2sgb24gdGhlIGNsaWVudC4KIiIiCmltcG9ydCBiYXNlNjQKaW1wb3J0IGpzb24KaW1wb3J0IG9zCmltcG9ydCBzdWJwcm9jZXNz"
    "CmltcG9ydCBzeXMKaW1wb3J0IHRpbWUKZnJvbSBzaHV0aWwgaW1wb3J0IHdoaWNoCgpJTlNUQUxMX0RJUiA9ICIvcm9vdC9uYXMt"
    "ZW5wLW1vdW50IgpCSU5fTkFNRSA9ICJuYXMtZW5wLW1vdW50LnB5IgpTRVJWSUNFX05BTUUgPSAibmFzLWVucC1tb3VudC5zZXJ2"
    "aWNlIgoKIyAtLS0tIEVtYmVkZGVkIGJsb2IgKGZpbGxlZCBpbiBieSB0aGUgZ2VuZXJhdG9yKSAtLS0tCkJMT0JfQ0lQSEVSID0g"
    "Il9fQ0lQSEVSVEVYVF9fIgpCTE9CX05PTkNFID0gIl9fTk9OQ0VfXyIKQkxPQl9LRVlBID0gIl9fS0VZQV9fIgpCTE9CX0tFWVBB"
    "RCA9ICJfX0tFWVBBRF9fIgoKCmRlZiBsb2dmKG1zZyk6CiAgICBwcmludChmIltuYXMtZW5wLW1vdW50XSB7bXNnfSIsIGZpbGU9"
    "c3lzLnN0ZGVycikKCgpkZWYgX3BpcF9pbnN0YWxsKHBrZyk6CiAgICByID0gc3VicHJvY2Vzcy5ydW4oW3N5cy5leGVjdXRhYmxl"
    "LCAiLW0iLCAicGlwIiwgImluc3RhbGwiLCAiLS1xdWlldCIsIHBrZ10sCiAgICAgICAgICAgICAgICAgICAgICAgIGNhcHR1cmVf"
    "b3V0cHV0PVRydWUsIHRleHQ9VHJ1ZSkKICAgIGlmIHIucmV0dXJuY29kZSAhPSAwOgogICAgICAgICMgcGlwIG1vZHVsZSBtYXkg"
    "YmUgbWlzc2luZyBlbnRpcmVseSBvbiBhIG1pbmltYWwgaW1hZ2U7IGJvb3RzdHJhcCBpdCBvbmNlLgogICAgICAgIHN1YnByb2Nl"
    "c3MucnVuKFtzeXMuZXhlY3V0YWJsZSwgIi1tIiwgImVuc3VyZXBpcCIsICItLWRlZmF1bHQtcGlwIl0sCiAgICAgICAgICAgICAg"
    "ICAgICAgICAgIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRleHQ9VHJ1ZSkKICAgICAgICByID0gc3VicHJvY2Vzcy5ydW4oW3N5cy5l"
    "eGVjdXRhYmxlLCAiLW0iLCAicGlwIiwgImluc3RhbGwiLCAiLS1xdWlldCIsIHBrZ10sCiAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgICBjYXB0dXJlX291dHB1dD1UcnVlLCB0ZXh0PVRydWUpCiAgICByZXR1cm4gcgoKCmRlZiBlbnN1cmVfY3J5cHRvKCk6CiAg"
    "ICB0cnk6CiAgICAgICAgZnJvbSBjcnlwdG9ncmFwaHkuaGF6bWF0LnByaW1pdGl2ZXMuY2lwaGVycy5hZWFkIGltcG9ydCBBRVNH"
    "Q00KICAgICAgICByZXR1cm4gQUVTR0NNCiAgICBleGNlcHQgSW1wb3J0RXJyb3I6CiAgICAgICAgbG9nZigiY3J5cHRvZ3JhcGh5"
    "IHBhY2thZ2UgbWlzc2luZzsgaW5zdGFsbGluZyB2aWEgcGlwIC4uLiIpCiAgICAgICAgciA9IF9waXBfaW5zdGFsbCgiY3J5cHRv"
    "Z3JhcGh5IikKICAgICAgICBpZiByLnJldHVybmNvZGUgIT0gMDoKICAgICAgICAgICAgbG9nZihmImZhdGFsOiBwaXAgaW5zdGFs"
    "bCBjcnlwdG9ncmFwaHkgZmFpbGVkOlxue3Iuc3Rkb3V0fXtyLnN0ZGVycn0iKQogICAgICAgICAgICBzeXMuZXhpdCgyKQogICAg"
    "ICAgIHRyeToKICAgICAgICAgICAgZnJvbSBjcnlwdG9ncmFwaHkuaGF6bWF0LnByaW1pdGl2ZXMuY2lwaGVycy5hZWFkIGltcG9y"
    "dCBBRVNHQ00KICAgICAgICAgICAgcmV0dXJuIEFFU0dDTQogICAgICAgIGV4Y2VwdCBJbXBvcnRFcnJvcjoKICAgICAgICAgICAg"
    "bG9nZigiZmF0YWw6IGNyeXB0b2dyYXBoeSBzdGlsbCBub3QgaW1wb3J0YWJsZSBhZnRlciBpbnN0YWxsIikKICAgICAgICAgICAg"
    "c3lzLmV4aXQoMikKCgpBRVNHQ00gPSBlbnN1cmVfY3J5cHRvKCkKCgpkZWYgZGVjb2RlX2I2NChzKToKICAgIHRyeToKICAgICAg"
    "ICByZXR1cm4gYmFzZTY0LmI2NGRlY29kZShzKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIGxvZ2YoZiJmYXRh"
    "bDogYmxvYiBkZWNvZGUgZXJyb3I6IHtlfSIpCiAgICAgICAgc3lzLmV4aXQoMikKCgpkZWYgbG9hZF9jb25maWcoKToKICAgIGtl"
    "eV9hID0gZGVjb2RlX2I2NChCTE9CX0tFWUEpCiAgICBrZXlfcGFkID0gZGVjb2RlX2I2NChCTE9CX0tFWVBBRCkKICAgIGlmIGxl"
    "bihrZXlfYSkgIT0gbGVuKGtleV9wYWQpOgogICAgICAgIHJhaXNlIFJ1bnRpbWVFcnJvcigia2V5IG1hdGVyaWFsIGxlbmd0aCBt"
    "aXNtYXRjaCIpCiAgICBrZXkgPSBieXRlYXJyYXkoYSBeIGIgZm9yIGEsIGIgaW4gemlwKGtleV9hLCBrZXlfcGFkKSkKICAgIHRy"
    "eToKICAgICAgICBwbGFpbiA9IEFFU0dDTShieXRlcyhrZXkpKS5kZWNyeXB0KGRlY29kZV9iNjQoQkxPQl9OT05DRSksIGRlY29k"
    "ZV9iNjQoQkxPQl9DSVBIRVIpLCBOb25lKQogICAgZXhjZXB0IEV4Y2VwdGlvbiBhcyBlOgogICAgICAgIHJhaXNlIFJ1bnRpbWVF"
    "cnJvcihmImNvbmZpZyBhdXRoL2RlY3J5cHQgZmFpbGVkOiB7ZX0iKQogICAgZmluYWxseToKICAgICAgICAjIGJlc3QtZWZmb3J0"
    "IHplcm9pbmcgb2YgdGhlIG11dGFibGUgY29weTsgdGhlIGJ5dGVzKCkgY29weSBwYXNzZWQgdG8KICAgICAgICAjIEFFU0dDTSBh"
    "Ym92ZSBpcyBpbW11dGFibGUgYW5kIGNhbid0IGJlIHplcm9lZCB0aGUgc2FtZSB3YXkKICAgICAgICBmb3IgaSBpbiByYW5nZShs"
    "ZW4oa2V5KSk6CiAgICAgICAgICAgIGtleVtpXSA9IDAKICAgIHJldHVybiBqc29uLmxvYWRzKHBsYWluKQoKCmRlZiByZXF1aXJl"
    "X3Jvb3QoKToKICAgIGlmIG9zLmdldGV1aWQoKSAhPSAwOgogICAgICAgIGxvZ2YoImZhdGFsOiBtdXN0IGJlIHJ1biBhcyByb290"
    "IikKICAgICAgICBzeXMuZXhpdCgxKQoKCmRlZiBpc19tb3VudGVkKHRhcmdldCk6CiAgICB0cnk6CiAgICAgICAgd2l0aCBvcGVu"
    "KCIvcHJvYy9tb3VudHMiKSBhcyBmOgogICAgICAgICAgICBkYXRhID0gZi5yZWFkKCkKICAgIGV4Y2VwdCBPU0Vycm9yOgogICAg"
    "ICAgIHJldHVybiBGYWxzZQogICAgYWJzX3RhcmdldCA9IG9zLnBhdGguYWJzcGF0aCh0YXJnZXQpCiAgICBmb3IgbGluZSBpbiBk"
    "YXRhLnNwbGl0bGluZXMoKToKICAgICAgICBmaWVsZHMgPSBsaW5lLnNwbGl0KCkKICAgICAgICBpZiBsZW4oZmllbGRzKSA+PSAy"
    "IGFuZCBmaWVsZHNbMV0gaW4gKGFic190YXJnZXQsIHRhcmdldCk6CiAgICAgICAgICAgIHJldHVybiBUcnVlCiAgICByZXR1cm4g"
    "RmFsc2UKCgpkZWYgaGF2ZV9jbWQobmFtZSk6CiAgICByZXR1cm4gd2hpY2gobmFtZSkgaXMgbm90IE5vbmUKCgpkZWYgZW5zdXJl"
    "X2RlcHMoY2ZnKToKICAgIGlmIGNmZ1sicHJvdG9jb2wiXSA9PSAiY2lmcyIgYW5kIG5vdCBoYXZlX2NtZCgibW91bnQuY2lmcyIp"
    "OgogICAgICAgIGlmIGNmZy5nZXQoImluc3RhbGxfZGVwcyIpIGFuZCBoYXZlX2NtZCgiYXB0LWdldCIpOgogICAgICAgICAgICBs"
    "b2dmKCJtb3VudC5jaWZzIG1pc3Npbmc7IGluc3RhbGxpbmcgY2lmcy11dGlscyAuLi4iKQogICAgICAgICAgICBlbnYgPSBkaWN0"
    "KG9zLmVudmlyb24sIERFQklBTl9GUk9OVEVORD0ibm9uaW50ZXJhY3RpdmUiKQogICAgICAgICAgICByID0gc3VicHJvY2Vzcy5y"
    "dW4oWyJhcHQtZ2V0IiwgImluc3RhbGwiLCAiLXkiLCAiY2lmcy11dGlscyJdLAogICAgICAgICAgICAgICAgICAgICAgICAgICAg"
    "ICAgIGVudj1lbnYsIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRleHQ9VHJ1ZSkKICAgICAgICAgICAgaWYgci5yZXR1cm5jb2RlICE9"
    "IDA6CiAgICAgICAgICAgICAgICBsb2dmKGYid2FybjogY2lmcy11dGlscyBpbnN0YWxsIGZhaWxlZDoge3IucmV0dXJuY29kZX1c"
    "bntyLnN0ZG91dH17ci5zdGRlcnJ9IikKICAgICAgICBlbHNlOgogICAgICAgICAgICBsb2dmKCJ3YXJuOiBtb3VudC5jaWZzIG5v"
    "dCBmb3VuZDsgaW5zdGFsbCBjaWZzLXV0aWxzIChhcHQtZ2V0IGluc3RhbGwgY2lmcy11dGlscykiKQoKCmRlZiBidWlsZF9zb3Vy"
    "Y2UoY2ZnLCBtKToKICAgIGlmIGNmZ1sicHJvdG9jb2wiXSA9PSAibmZzIjoKICAgICAgICByZXR1cm4gZid7Y2ZnWyJob3N0Il19"
    "OnttWyJyZW1vdGUiXX0nCiAgICByZW0gPSBtWyJyZW1vdGUiXS5sc3RyaXAoIi8iKQogICAgcmV0dXJuIGYnLy97Y2ZnWyJob3N0"
    "Il19L3tyZW19JwoKCmRlZiBtb3VudF9vbmUoY2ZnLCBtKToKICAgIGlmIGlzX21vdW50ZWQobVsibG9jYWwiXSk6CiAgICAgICAg"
    "bG9nZihmJ2FscmVhZHkgbW91bnRlZDoge21bImxvY2FsIl19JykKICAgICAgICByZXR1cm4gTm9uZQogICAgdHJ5OgogICAgICAg"
    "IG9zLm1ha2VkaXJzKG1bImxvY2FsIl0sIG1vZGU9MG83NTUsIGV4aXN0X29rPVRydWUpCiAgICBleGNlcHQgT1NFcnJvciBhcyBl"
    "OgogICAgICAgIHJldHVybiBmJ21rZGlyIHttWyJsb2NhbCJdfToge2V9JwoKICAgIG9wdHMgPSBjZmcuZ2V0KCJkZWZhdWx0X29w"
    "dGlvbnMiLCAiIikKICAgIGlmIG0uZ2V0KCJvcHRpb25zIiwgIiIpLnN0cmlwKCk6CiAgICAgICAgb3B0cyA9IG1bIm9wdGlvbnMi"
    "XQoKICAgIHNyYyA9IGJ1aWxkX3NvdXJjZShjZmcsIG0pCiAgICBpZiBjZmdbInByb3RvY29sIl0gPT0gImNpZnMiOgogICAgICAg"
    "IHBhcnRzID0gW10KICAgICAgICBpZiBvcHRzOgogICAgICAgICAgICBwYXJ0cy5hcHBlbmQob3B0cykKICAgICAgICBwYXJ0cy5h"
    "cHBlbmQoInVzZXJuYW1lPSIgKyBjZmdbInVzZXJuYW1lIl0pCiAgICAgICAgaWYgY2ZnLmdldCgiZG9tYWluIik6CiAgICAgICAg"
    "ICAgIHBhcnRzLmFwcGVuZCgiZG9tYWluPSIgKyBjZmdbImRvbWFpbiJdKQogICAgICAgIGZ1bGwgPSAiLCIuam9pbihwYXJ0cykK"
    "ICAgICAgICBlbnYgPSBkaWN0KG9zLmVudmlyb24sIFBBU1NXRD1jZmcuZ2V0KCJwYXNzd29yZCIsICIiKSkKICAgICAgICBjbWQg"
    "PSBbIm1vdW50LmNpZnMiLCBzcmMsIG1bImxvY2FsIl0sICItbyIsIGZ1bGxdCiAgICBlbHNlOgogICAgICAgIGFyZ3MgPSBbIi10"
    "IiwgIm5mcyJdCiAgICAgICAgaWYgb3B0czoKICAgICAgICAgICAgYXJncyArPSBbIi1vIiwgb3B0c10KICAgICAgICBhcmdzICs9"
    "IFtzcmMsIG1bImxvY2FsIl1dCiAgICAgICAgY21kID0gWyJtb3VudCJdICsgYXJncwogICAgICAgIGVudiA9IG9zLmVudmlyb24u"
    "Y29weSgpCgogICAgciA9IHN1YnByb2Nlc3MucnVuKGNtZCwgZW52PWVudiwgY2FwdHVyZV9vdXRwdXQ9VHJ1ZSwgdGV4dD1UcnVl"
    "KQogICAgaWYgci5yZXR1cm5jb2RlICE9IDA6CiAgICAgICAgcmV0dXJuIGYnbW91bnQge3NyY30gLT4ge21bImxvY2FsIl19IGZh"
    "aWxlZDoge3IucmV0dXJuY29kZX06IHsoci5zdGRvdXQgKyByLnN0ZGVycikuc3RyaXAoKX0nCiAgICBsb2dmKGYnbW91bnRlZCB7"
    "c3JjfSAtPiB7bVsibG9jYWwiXX0nKQogICAgcmV0dXJuIE5vbmUKCgpkZWYgb25lc2hvdCgpOgogICAgcmVxdWlyZV9yb290KCkK"
    "ICAgIHRyeToKICAgICAgICBjZmcgPSBsb2FkX2NvbmZpZygpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAgICAgbG9n"
    "ZihmImZhdGFsOiB7ZX0iKQogICAgICAgIHJldHVybiAyCiAgICBlbnN1cmVfZGVwcyhjZmcpCgogICAgYXR0ZW1wdHMgPSBjZmcu"
    "Z2V0KCJyZXRyeV9hdHRlbXB0cyIpIG9yIDEKICAgIGlmIGF0dGVtcHRzIDwgMToKICAgICAgICBhdHRlbXB0cyA9IDEKICAgIGRl"
    "bGF5ID0gY2ZnLmdldCgicmV0cnlfZGVsYXlfc2VjIikgb3IgNQogICAgaWYgZGVsYXkgPD0gMDoKICAgICAgICBkZWxheSA9IDUK"
    "CiAgICBwZW5kaW5nID0gbGlzdChjZmdbIm1vdW50cyJdKQogICAgbGFzdF9lcnIgPSBOb25lCiAgICBhdHRlbXB0ID0gMQogICAg"
    "d2hpbGUgYXR0ZW1wdCA8PSBhdHRlbXB0cyBhbmQgcGVuZGluZzoKICAgICAgICBzdGlsbF9wZW5kaW5nID0gW10KICAgICAgICBm"
    "b3IgbSBpbiBwZW5kaW5nOgogICAgICAgICAgICBlcnIgPSBtb3VudF9vbmUoY2ZnLCBtKQogICAgICAgICAgICBpZiBlcnI6CiAg"
    "ICAgICAgICAgICAgICBsb2dmKGYiYXR0ZW1wdCB7YXR0ZW1wdH0ve2F0dGVtcHRzfToge2Vycn0iKQogICAgICAgICAgICAgICAg"
    "bGFzdF9lcnIgPSBlcnIKICAgICAgICAgICAgICAgIHN0aWxsX3BlbmRpbmcuYXBwZW5kKG0pCiAgICAgICAgcGVuZGluZyA9IHN0"
    "aWxsX3BlbmRpbmcKICAgICAgICBpZiBwZW5kaW5nIGFuZCBhdHRlbXB0IDwgYXR0ZW1wdHM6CiAgICAgICAgICAgIGQgPSBtaW4o"
    "ZGVsYXkgKiBhdHRlbXB0LCA2MCkKICAgICAgICAgICAgbG9nZihmIntsZW4ocGVuZGluZyl9IG1vdW50KHMpIHBlbmRpbmcsIHJl"
    "dHJ5aW5nIGluIHtkfXMgLi4uIikKICAgICAgICAgICAgdGltZS5zbGVlcChkKQogICAgICAgIGF0dGVtcHQgKz0gMQoKICAgIGlm"
    "IHBlbmRpbmc6CiAgICAgICAgbG9nZihmImdpdmluZyB1cDoge2xlbihwZW5kaW5nKX0gbW91bnQocykgc3RpbGwgbm90IG1vdW50"
    "ZWQgKGxhc3QgZXJyb3I6IHtsYXN0X2Vycn0pIikKICAgICAgICByZXR1cm4gMSAgIyBub256ZXJvLCBidXQgYm9vdCBpcyB1bmFm"
    "ZmVjdGVkIGJlY2F1c2Ugbm90aGluZyBkZXBlbmRzIG9uIHRoaXMgdW5pdAogICAgbG9nZigiYWxsIG1vdW50cyB1cCIpCiAgICBy"
    "ZXR1cm4gMAoKCmRlZiBzdGF0dXMoKToKICAgIHRyeToKICAgICAgICBjZmcgPSBsb2FkX2NvbmZpZygpCiAgICBleGNlcHQgRXhj"
    "ZXB0aW9uIGFzIGU6CiAgICAgICAgbG9nZihmImZhdGFsOiB7ZX0iKQogICAgICAgIHJldHVybiAyCiAgICBmb3IgbSBpbiBjZmdb"
    "Im1vdW50cyJdOgogICAgICAgIHN0YXRlID0gIm1vdW50ZWQiIGlmIGlzX21vdW50ZWQobVsibG9jYWwiXSkgZWxzZSAiTk9UIG1v"
    "dW50ZWQiCiAgICAgICAgcHJpbnQoZid7bVsibG9jYWwiXTo8MzB9IHtzdGF0ZX0nKQogICAgcmV0dXJuIDAKCgpkZWYgc2VsZnRl"
    "c3QoKToKICAgIHRyeToKICAgICAgICBjZmcgPSBsb2FkX2NvbmZpZygpCiAgICBleGNlcHQgRXhjZXB0aW9uIGFzIGU6CiAgICAg"
    "ICAgbG9nZihmInNlbGZ0ZXN0IEZBSUxFRDoge2V9IikKICAgICAgICByZXR1cm4gMgogICAgaG9zdCA9IGNmZy5nZXQoImhvc3Qi"
    "LCAiIikKICAgIG1hc2tlZCA9IChob3N0WzBdICsgIioqKiIpIGlmIGhvc3QgZWxzZSAiPyIKICAgIHByaW50KGYnY29uZmlnIGRl"
    "Y3J5cHRlZCBPSzogcHJvdG9jb2w9e2NmZ1sicHJvdG9jb2wiXX0gaG9zdD17bWFza2VkfSBtb3VudHM9e2xlbihjZmdbIm1vdW50"
    "cyJdKX0nKQogICAgcmV0dXJuIDAKCgpVTklUX1RFTVBMQVRFID0gIiIiW1VuaXRdCkRlc2NyaXB0aW9uPU5BUyBhdXRvIG1vdW50"
    "IChuYXMtZW5wLW1vdW50KQpBZnRlcj1uZXR3b3JrLW9ubGluZS50YXJnZXQKV2FudHM9bmV0d29yay1vbmxpbmUudGFyZ2V0CiMg"
    "SW50ZW50aW9uYWxseSBubyBSZXF1aXJlcyBmcm9tIG90aGVyIHVuaXRzIC0+IGZhaWx1cmVzIG5ldmVyIGJsb2NrIGJvb3QuClN0"
    "YXJ0TGltaXRJbnRlcnZhbFNlYz0wCgpbU2VydmljZV0KVHlwZT1vbmVzaG90ClJlbWFpbkFmdGVyRXhpdD15ZXMKRXhlY1N0YXJ0"
    "PXtweXRob259IHtzY3JpcHR9IC0tb25lc2hvdAojIEJvdW5kZWQgc28gYSBkZWFkIE5BUyBjYW4gbmV2ZXIgaGFuZyBib290OyBy"
    "ZXRyaWVzIGhhcHBlbiBpbnNpZGUgdGhpcyBidWRnZXQuClRpbWVvdXRTdGFydFNlYz0xNTAKCltJbnN0YWxsXQpXYW50ZWRCeT1t"
    "dWx0aS11c2VyLnRhcmdldAoiIiIKCgpkZWYgaW5zdGFsbF9zZXJ2aWNlKCk6CiAgICByZXF1aXJlX3Jvb3QoKQogICAgdHJ5Ogog"
    "ICAgICAgIGxvYWRfY29uZmlnKCkKICAgIGV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgICAgICBsb2dmKGYicmVmdXNpbmcgdG8g"
    "aW5zdGFsbDoge2V9IikKICAgICAgICByZXR1cm4gMgogICAgb3MubWFrZWRpcnMoSU5TVEFMTF9ESVIsIG1vZGU9MG83MDAsIGV4"
    "aXN0X29rPVRydWUpCiAgICB0YXJnZXQgPSBvcy5wYXRoLmpvaW4oSU5TVEFMTF9ESVIsIEJJTl9OQU1FKQogICAgc2VsZl9wYXRo"
    "ID0gb3MucGF0aC5hYnNwYXRoKF9fZmlsZV9fKQogICAgaWYgc2VsZl9wYXRoICE9IHRhcmdldDoKICAgICAgICB3aXRoIG9wZW4o"
    "c2VsZl9wYXRoLCAicmIiKSBhcyBmOgogICAgICAgICAgICBkYXRhID0gZi5yZWFkKCkKICAgICAgICB3aXRoIG9wZW4odGFyZ2V0"
    "LCAid2IiKSBhcyBmOgogICAgICAgICAgICBmLndyaXRlKGRhdGEpCiAgICAgICAgb3MuY2htb2QodGFyZ2V0LCAwbzcwMCkKICAg"
    "ICAgICBsb2dmKGYiaW5zdGFsbGVkIHNjcmlwdCB0byB7dGFyZ2V0fSIpCgogICAgdW5pdCA9IFVOSVRfVEVNUExBVEUuZm9ybWF0"
    "KHB5dGhvbj1zeXMuZXhlY3V0YWJsZSwgc2NyaXB0PXRhcmdldCkKICAgIHVuaXRfcGF0aCA9IGYiL2V0Yy9zeXN0ZW1kL3N5c3Rl"
    "bS97U0VSVklDRV9OQU1FfSIKICAgIHdpdGggb3Blbih1bml0X3BhdGgsICJ3IikgYXMgZjoKICAgICAgICBmLndyaXRlKHVuaXQp"
    "CiAgICBsb2dmKGYid3JvdGUge3VuaXRfcGF0aH0iKQogICAgZm9yIGFyZ3MgaW4gKFsiZGFlbW9uLXJlbG9hZCJdLCBbImVuYWJs"
    "ZSIsIFNFUlZJQ0VfTkFNRV0sIFsic3RhcnQiLCBTRVJWSUNFX05BTUVdKToKICAgICAgICByID0gc3VicHJvY2Vzcy5ydW4oWyJz"
    "eXN0ZW1jdGwiXSArIGFyZ3MsIGNhcHR1cmVfb3V0cHV0PVRydWUsIHRleHQ9VHJ1ZSkKICAgICAgICBpZiByLnJldHVybmNvZGUg"
    "IT0gMDoKICAgICAgICAgICAgbG9nZihmIndhcm46IHN5c3RlbWN0bCB7YXJnc306IHtyLnJldHVybmNvZGV9OiB7KHIuc3Rkb3V0"
    "ICsgci5zdGRlcnIpLnN0cmlwKCl9IikKICAgIGxvZ2YoZiJzZXJ2aWNlIGluc3RhbGxlZCBhbmQgc3RhcnRlZC4gQ2hlY2s6IHN5"
    "c3RlbWN0bCBzdGF0dXMge1NFUlZJQ0VfTkFNRX0iKQogICAgcmV0dXJuIDAKCgpkZWYgdW5pbnN0YWxsKCk6CiAgICByZXF1aXJl"
    "X3Jvb3QoKQogICAgc3VicHJvY2Vzcy5ydW4oWyJzeXN0ZW1jdGwiLCAiZGlzYWJsZSIsICItLW5vdyIsIFNFUlZJQ0VfTkFNRV0s"
    "IGNhcHR1cmVfb3V0cHV0PVRydWUpCiAgICB0cnk6CiAgICAgICAgb3MucmVtb3ZlKGYiL2V0Yy9zeXN0ZW1kL3N5c3RlbS97U0VS"
    "VklDRV9OQU1FfSIpCiAgICBleGNlcHQgT1NFcnJvcjoKICAgICAgICBwYXNzCiAgICBzdWJwcm9jZXNzLnJ1bihbInN5c3RlbWN0"
    "bCIsICJkYWVtb24tcmVsb2FkIl0sIGNhcHR1cmVfb3V0cHV0PVRydWUpCiAgICB0cnk6CiAgICAgICAgY2ZnID0gbG9hZF9jb25m"
    "aWcoKQogICAgICAgIGZvciBtIGluIGNmZ1sibW91bnRzIl06CiAgICAgICAgICAgIGlmIGlzX21vdW50ZWQobVsibG9jYWwiXSk6"
    "CiAgICAgICAgICAgICAgICByID0gc3VicHJvY2Vzcy5ydW4oWyJ1bW91bnQiLCBtWyJsb2NhbCJdXSwgY2FwdHVyZV9vdXRwdXQ9"
    "VHJ1ZSwgdGV4dD1UcnVlKQogICAgICAgICAgICAgICAgaWYgci5yZXR1cm5jb2RlICE9IDA6CiAgICAgICAgICAgICAgICAgICAg"
    "bG9nZihmJ3dhcm46IHVtb3VudCB7bVsibG9jYWwiXX06IHtyLnJldHVybmNvZGV9OiB7KHIuc3Rkb3V0ICsgci5zdGRlcnIpLnN0"
    "cmlwKCl9JykKICAgICAgICAgICAgICAgIGVsc2U6CiAgICAgICAgICAgICAgICAgICAgbG9nZihmJ3VubW91bnRlZCB7bVsibG9j"
    "YWwiXX0nKQogICAgZXhjZXB0IEV4Y2VwdGlvbjoKICAgICAgICBwYXNzCiAgICBsb2dmKCJ1bmluc3RhbGxlZCIpCiAgICByZXR1"
    "cm4gMAoKCmRlZiB1c2FnZSgpOgogICAgcHJpbnQoIiIibmFzLWVucC1tb3VudAogIChubyBhcmdzKSAvIC0tb25lc2hvdCAgIG1v"
    "dW50IGFsbCBzaGFyZXMgb25jZSAod2l0aCBpbnRlcm5hbCByZXRyaWVzKQogIC0taW5zdGFsbC1zZXJ2aWNlICAgICAgIGluc3Rh"
    "bGwgJiBlbmFibGUgc3lzdGVtZCBib290IHNlcnZpY2UKICAtLXVuaW5zdGFsbCAgICAgICAgICAgICBzdG9wIHNlcnZpY2UsIHJl"
    "bW92ZSB1bml0LCB1bm1vdW50IHNoYXJlcwogIC0tc3RhdHVzICAgICAgICAgICAgICAgIHNob3cgbW91bnQgc3RhdHVzCiAgLS1z"
    "ZWxmdGVzdCAgICAgICAgICAgICAgdmVyaWZ5IGVtYmVkZGVkIGNvbmZpZyBkZWNyeXB0cyAobm8gc2VjcmV0cyBwcmludGVkKSIi"
    "IikKCgpkZWYgbWFpbigpOgogICAgbW9kZSA9IHN5cy5hcmd2WzFdIGlmIGxlbihzeXMuYXJndikgPiAxIGVsc2UgIi0tb25lc2hv"
    "dCIKICAgIGlmIG1vZGUgaW4gKCItLW9uZXNob3QiLCAiIik6CiAgICAgICAgc3lzLmV4aXQob25lc2hvdCgpKQogICAgZWxpZiBt"
    "b2RlID09ICItLWluc3RhbGwtc2VydmljZSI6CiAgICAgICAgc3lzLmV4aXQoaW5zdGFsbF9zZXJ2aWNlKCkpCiAgICBlbGlmIG1v"
    "ZGUgPT0gIi0tdW5pbnN0YWxsIjoKICAgICAgICBzeXMuZXhpdCh1bmluc3RhbGwoKSkKICAgIGVsaWYgbW9kZSA9PSAiLS1zdGF0"
    "dXMiOgogICAgICAgIHN5cy5leGl0KHN0YXR1cygpKQogICAgZWxpZiBtb2RlID09ICItLXNlbGZ0ZXN0IjoKICAgICAgICBzeXMu"
    "ZXhpdChzZWxmdGVzdCgpKQogICAgZWxpZiBtb2RlIGluICgiLWgiLCAiLS1oZWxwIiwgImhlbHAiKToKICAgICAgICB1c2FnZSgp"
    "CiAgICBlbHNlOgogICAgICAgIHVzYWdlKCkKICAgICAgICBzeXMuZXhpdCgyKQoKCmlmIF9fbmFtZV9fID09ICJfX21haW5fXyI6"
    "CiAgICBtYWluKCkK"
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
            with open(out_abs, "w") as f:
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
    with open(out_abs, "w") as f:
        f.write(src)
    os.chmod(out_abs, 0o700)

    print(f"\n[emit] Client script written to: {out_abs}")
    print(deploy_instructions(out_abs))

if __name__ == "__main__":
    main()
