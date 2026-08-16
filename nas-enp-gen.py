#!/usr/bin/env python3
"""
nas-enp-mount generator (server side)
Collects NAS connection details + mount mappings, encrypts them
(AES-256-GCM), and compiles a single stripped static Go binary that embeds
the ciphertext.

The generated binary decrypts the config only in memory at run time; the
plaintext IP / account / password never sit on the client's disk, and
`strings` on the binary reveals nothing.

SECURITY REALITY CHECK
----------------------
This is obfuscation, not unbreakable secrecy. A client that can mount the
share must be able to produce the credentials, so anyone with root on that
client can still recover them (RAM dump, strace, packet capture). Treat the
binary as "raises the bar a lot", and pair it with a DEDICATED, LEAST-
PRIVILEGE, REVOCABLE NAS account so a leak is small and you can kill it by
changing one password on the NAS.

Requirements on this machine:
  - Python 3.8+  with the `cryptography` package  (pip install cryptography)
  - PySide6, for the GUI (auto-installed via pip on first GUI launch;
    not needed for --config/--cli headless use)
  - Go toolchain (https://go.dev/dl/) to compile. Cross-compiles to any arch.
    Without Go, use --no-build (CLI) or the "emit Go source only" checkbox
    (GUI) to emit source and compile on any Linux box.

Requirements on each client machine:
  - Debian/Ubuntu Linux, root access. No Python, no runtime deps — the
    binary is static.

Usage:
  python3 nas-enp-gen.py                       # launch the GUI
  python3 nas-enp-gen.py --cli                  # interactive terminal prompts
  python3 nas-enp-gen.py --config nas.json      # from a JSON file, headless
  python3 nas-enp-gen.py --config nas.json --arch amd64,arm64
  python3 nas-enp-gen.py --config nas.json --no-build   # emit Go source only
"""
import argparse, base64, getpass, json, os, shutil, subprocess, sys, tempfile

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Missing dependency. Run:  pip install cryptography")

# ---- Embedded Go client template (base64) ----
GO_TEMPLATE_B64 = (
    "cGFja2FnZSBtYWluCgovLyBuYXMtZW5wLW1vdW50IGNsaWVudAovLyBCdWlsdCBmcm9tIGFuIGVuY3J5cHRlZCBjb25maWcgYmxv"
    "YiBlbWJlZGRlZCBhdCBnZW5lcmF0aW9uIHRpbWUuCi8vIFRoZSBwbGFpbnRleHQgY29uZmlnIG5ldmVyIHRvdWNoZXMgZGlzayBv"
    "biB0aGUgY2xpZW50LgoKaW1wb3J0ICgKCSJjcnlwdG8vYWVzIgoJImNyeXB0by9jaXBoZXIiCgkiZW5jb2RpbmcvYmFzZTY0IgoJ"
    "ImVuY29kaW5nL2pzb24iCgkiZm10IgoJIm9zIgoJIm9zL2V4ZWMiCgkicGF0aC9maWxlcGF0aCIKCSJzdHJpbmdzIgoJInRpbWUi"
    "CikKCi8vIC0tLS0gRW1iZWRkZWQgYmxvYiAoZmlsbGVkIGluIGJ5IHRoZSBnZW5lcmF0b3IpIC0tLS0KdmFyICgKCWJsb2JDaXBo"
    "ZXIgPSAiX19DSVBIRVJURVhUX18iCglibG9iTm9uY2UgID0gIl9fTk9OQ0VfXyIKCWJsb2JLZXlBICAgPSAiX19LRVlBX18iCgli"
    "bG9iS2V5UGFkID0gIl9fS0VZUEFEX18iCikKCmNvbnN0IGluc3RhbGxEaXIgPSAiL3Jvb3QvbmFzLWVucC1tb3VudCIKY29uc3Qg"
    "YmluTmFtZSA9ICJuYXMtZW5wLW1vdW50Igpjb25zdCBzZXJ2aWNlTmFtZSA9ICJuYXMtZW5wLW1vdW50LnNlcnZpY2UiCgp0eXBl"
    "IE1vdW50U3BlYyBzdHJ1Y3QgewoJUmVtb3RlICBzdHJpbmcgYGpzb246InJlbW90ZSJgCglMb2NhbCAgIHN0cmluZyBganNvbjoi"
    "bG9jYWwiYAoJT3B0aW9ucyBzdHJpbmcgYGpzb246Im9wdGlvbnMiYAp9Cgp0eXBlIENvbmZpZyBzdHJ1Y3QgewoJUHJvdG9jb2wg"
    "ICAgICAgc3RyaW5nICAgICAgYGpzb246InByb3RvY29sImAgLy8gImNpZnMiIG9yICJuZnMiCglIb3N0ICAgICAgICAgICBzdHJp"
    "bmcgICAgICBganNvbjoiaG9zdCJgCglVc2VybmFtZSAgICAgICBzdHJpbmcgICAgICBganNvbjoidXNlcm5hbWUiYAoJUGFzc3dv"
    "cmQgICAgICAgc3RyaW5nICAgICAgYGpzb246InBhc3N3b3JkImAKCURvbWFpbiAgICAgICAgIHN0cmluZyAgICAgIGBqc29uOiJk"
    "b21haW4iYAoJRGVmYXVsdE9wdGlvbnMgc3RyaW5nICAgICAgYGpzb246ImRlZmF1bHRfb3B0aW9ucyJgCglNb3VudHMgICAgICAg"
    "ICBbXU1vdW50U3BlYyBganNvbjoibW91bnRzImAKCVJldHJ5QXR0ZW1wdHMgIGludCAgICAgICAgIGBqc29uOiJyZXRyeV9hdHRl"
    "bXB0cyJgCglSZXRyeURlbGF5U2VjICBpbnQgICAgICAgICBganNvbjoicmV0cnlfZGVsYXlfc2VjImAKCUluc3RhbGxEZXBzICAg"
    "IGJvb2wgICAgICAgIGBqc29uOiJpbnN0YWxsX2RlcHMiYAp9CgpmdW5jIGxvZ2YoZm9ybWF0IHN0cmluZywgYSAuLi5pbnRlcmZh"
    "Y2V7fSkgewoJZm10LkZwcmludGYob3MuU3RkZXJyLCAiW25hcy1lbnAtbW91bnRdICIrZm9ybWF0KyJcbiIsIGEuLi4pCn0KCmZ1"
    "bmMgZGVjb2RlQjY0KHMgc3RyaW5nKSBbXWJ5dGUgewoJYiwgZXJyIDo9IGJhc2U2NC5TdGRFbmNvZGluZy5EZWNvZGVTdHJpbmco"
    "cykKCWlmIGVyciAhPSBuaWwgewoJCWxvZ2YoImZhdGFsOiBibG9iIGRlY29kZSBlcnJvcjogJXYiLCBlcnIpCgkJb3MuRXhpdCgy"
    "KQoJfQoJcmV0dXJuIGIKfQoKZnVuYyBsb2FkQ29uZmlnKCkgKCpDb25maWcsIGVycm9yKSB7CglrZXlBIDo9IGRlY29kZUI2NChi"
    "bG9iS2V5QSkKCWtleVBhZCA6PSBkZWNvZGVCNjQoYmxvYktleVBhZCkKCWlmIGxlbihrZXlBKSAhPSBsZW4oa2V5UGFkKSB7CgkJ"
    "cmV0dXJuIG5pbCwgZm10LkVycm9yZigia2V5IG1hdGVyaWFsIGxlbmd0aCBtaXNtYXRjaCIpCgl9CglrZXkgOj0gbWFrZShbXWJ5"
    "dGUsIGxlbihrZXlBKSkKCWZvciBpIDo9IHJhbmdlIGtleUEgewoJCWtleVtpXSA9IGtleUFbaV0gXiBrZXlQYWRbaV0KCX0KCWJs"
    "b2NrLCBlcnIgOj0gYWVzLk5ld0NpcGhlcihrZXkpCglpZiBlcnIgIT0gbmlsIHsKCQlyZXR1cm4gbmlsLCBlcnIKCX0KCWdjbSwg"
    "ZXJyIDo9IGNpcGhlci5OZXdHQ00oYmxvY2spCglpZiBlcnIgIT0gbmlsIHsKCQlyZXR1cm4gbmlsLCBlcnIKCX0KCXBsYWluLCBl"
    "cnIgOj0gZ2NtLk9wZW4obmlsLCBkZWNvZGVCNjQoYmxvYk5vbmNlKSwgZGVjb2RlQjY0KGJsb2JDaXBoZXIpLCBuaWwpCglpZiBl"
    "cnIgIT0gbmlsIHsKCQlyZXR1cm4gbmlsLCBmbXQuRXJyb3JmKCJjb25maWcgYXV0aC9kZWNyeXB0IGZhaWxlZDogJXciLCBlcnIp"
    "Cgl9Cgl2YXIgYyBDb25maWcKCWlmIGVyciA6PSBqc29uLlVubWFyc2hhbChwbGFpbiwgJmMpOyBlcnIgIT0gbmlsIHsKCQlyZXR1"
    "cm4gbmlsLCBlcnIKCX0KCS8vIHplcm8gdGhlIGtleQoJZm9yIGkgOj0gcmFuZ2Uga2V5IHsKCQlrZXlbaV0gPSAwCgl9CglyZXR1"
    "cm4gJmMsIG5pbAp9CgpmdW5jIHJlcXVpcmVSb290KCkgewoJaWYgb3MuR2V0ZXVpZCgpICE9IDAgewoJCWxvZ2YoImZhdGFsOiBt"
    "dXN0IGJlIHJ1biBhcyByb290IikKCQlvcy5FeGl0KDEpCgl9Cn0KCmZ1bmMgaXNNb3VudGVkKHRhcmdldCBzdHJpbmcpIGJvb2wg"
    "ewoJZGF0YSwgZXJyIDo9IG9zLlJlYWRGaWxlKCIvcHJvYy9tb3VudHMiKQoJaWYgZXJyICE9IG5pbCB7CgkJcmV0dXJuIGZhbHNl"
    "Cgl9CglhYnMsIF8gOj0gZmlsZXBhdGguQWJzKHRhcmdldCkKCWZvciBfLCBsaW5lIDo9IHJhbmdlIHN0cmluZ3MuU3BsaXQoc3Ry"
    "aW5nKGRhdGEpLCAiXG4iKSB7CgkJZmllbGRzIDo9IHN0cmluZ3MuRmllbGRzKGxpbmUpCgkJaWYgbGVuKGZpZWxkcykgPj0gMiB7"
    "CgkJCS8vIC9wcm9jL21vdW50cyBlc2NhcGVzIHNwYWNlcyBhcyBcMDQwOyBnb29kIGVub3VnaCBmb3IgdHlwaWNhbCBwYXRocwoJ"
    "CQlpZiBmaWVsZHNbMV0gPT0gYWJzIHx8IGZpZWxkc1sxXSA9PSB0YXJnZXQgewoJCQkJcmV0dXJuIHRydWUKCQkJfQoJCX0KCX0K"
    "CXJldHVybiBmYWxzZQp9CgpmdW5jIGhhdmVDbWQobmFtZSBzdHJpbmcpIGJvb2wgewoJXywgZXJyIDo9IGV4ZWMuTG9va1BhdGgo"
    "bmFtZSkKCXJldHVybiBlcnIgPT0gbmlsCn0KCmZ1bmMgZW5zdXJlRGVwcyhjICpDb25maWcpIHsKCWlmIGMuUHJvdG9jb2wgPT0g"
    "ImNpZnMiICYmICFoYXZlQ21kKCJtb3VudC5jaWZzIikgewoJCWlmIGMuSW5zdGFsbERlcHMgJiYgaGF2ZUNtZCgiYXB0LWdldCIp"
    "IHsKCQkJbG9nZigibW91bnQuY2lmcyBtaXNzaW5nOyBpbnN0YWxsaW5nIGNpZnMtdXRpbHMgLi4uIikKCQkJY21kIDo9IGV4ZWMu"
    "Q29tbWFuZCgiYXB0LWdldCIsICJpbnN0YWxsIiwgIi15IiwgImNpZnMtdXRpbHMiKQoJCQljbWQuRW52ID0gYXBwZW5kKG9zLkVu"
    "dmlyb24oKSwgIkRFQklBTl9GUk9OVEVORD1ub25pbnRlcmFjdGl2ZSIpCgkJCW91dCwgZXJyIDo9IGNtZC5Db21iaW5lZE91dHB1"
    "dCgpCgkJCWlmIGVyciAhPSBuaWwgewoJCQkJbG9nZigid2FybjogY2lmcy11dGlscyBpbnN0YWxsIGZhaWxlZDogJXZcbiVzIiwg"
    "ZXJyLCBzdHJpbmcob3V0KSkKCQkJfQoJCX0gZWxzZSB7CgkJCWxvZ2YoIndhcm46IG1vdW50LmNpZnMgbm90IGZvdW5kOyBpbnN0"
    "YWxsIGNpZnMtdXRpbHMgKGFwdC1nZXQgaW5zdGFsbCBjaWZzLXV0aWxzKSIpCgkJfQoJfQp9CgpmdW5jIGJ1aWxkU291cmNlKGMg"
    "KkNvbmZpZywgbSBNb3VudFNwZWMpIHN0cmluZyB7CglpZiBjLlByb3RvY29sID09ICJuZnMiIHsKCQlyZXR1cm4gZm10LlNwcmlu"
    "dGYoIiVzOiVzIiwgYy5Ib3N0LCBtLlJlbW90ZSkKCX0KCS8vIGNpZnMKCXJlbSA6PSBzdHJpbmdzLlRyaW1QcmVmaXgobS5SZW1v"
    "dGUsICIvIikKCXJldHVybiBmbXQuU3ByaW50ZigiLy8lcy8lcyIsIGMuSG9zdCwgcmVtKQp9CgpmdW5jIG1vdW50T25lKGMgKkNv"
    "bmZpZywgbSBNb3VudFNwZWMpIGVycm9yIHsKCWlmIGlzTW91bnRlZChtLkxvY2FsKSB7CgkJbG9nZigiYWxyZWFkeSBtb3VudGVk"
    "OiAlcyIsIG0uTG9jYWwpCgkJcmV0dXJuIG5pbAoJfQoJaWYgZXJyIDo9IG9zLk1rZGlyQWxsKG0uTG9jYWwsIDBvNzU1KTsgZXJy"
    "ICE9IG5pbCB7CgkJcmV0dXJuIGZtdC5FcnJvcmYoIm1rZGlyICVzOiAldyIsIG0uTG9jYWwsIGVycikKCX0KCglvcHRzIDo9IGMu"
    "RGVmYXVsdE9wdGlvbnMKCWlmIHN0cmluZ3MuVHJpbVNwYWNlKG0uT3B0aW9ucykgIT0gIiIgewoJCW9wdHMgPSBtLk9wdGlvbnMK"
    "CX0KCglzcmMgOj0gYnVpbGRTb3VyY2UoYywgbSkKCXZhciBjbWQgKmV4ZWMuQ21kCgoJaWYgYy5Qcm90b2NvbCA9PSAiY2lmcyIg"
    "ewoJCS8vIGNyZWRlbnRpYWxzIHZpYSBlbnZpcm9ubWVudCwgbmV2ZXIgYXJndi9kaXNrCgkJcGFydHMgOj0gW11zdHJpbmd7fQoJ"
    "CWlmIG9wdHMgIT0gIiIgewoJCQlwYXJ0cyA9IGFwcGVuZChwYXJ0cywgb3B0cykKCQl9CgkJcGFydHMgPSBhcHBlbmQocGFydHMs"
    "ICJ1c2VybmFtZT0iK2MuVXNlcm5hbWUpCgkJaWYgYy5Eb21haW4gIT0gIiIgewoJCQlwYXJ0cyA9IGFwcGVuZChwYXJ0cywgImRv"
    "bWFpbj0iK2MuRG9tYWluKQoJCX0KCQlmdWxsIDo9IHN0cmluZ3MuSm9pbihwYXJ0cywgIiwiKQoJCWNtZCA9IGV4ZWMuQ29tbWFu"
    "ZCgibW91bnQuY2lmcyIsIHNyYywgbS5Mb2NhbCwgIi1vIiwgZnVsbCkKCQljbWQuRW52ID0gYXBwZW5kKG9zLkVudmlyb24oKSwg"
    "IlBBU1NXRD0iK2MuUGFzc3dvcmQpCgl9IGVsc2UgewoJCWFyZ3MgOj0gW11zdHJpbmd7Ii10IiwgIm5mcyJ9CgkJaWYgb3B0cyAh"
    "PSAiIiB7CgkJCWFyZ3MgPSBhcHBlbmQoYXJncywgIi1vIiwgb3B0cykKCQl9CgkJYXJncyA9IGFwcGVuZChhcmdzLCBzcmMsIG0u"
    "TG9jYWwpCgkJY21kID0gZXhlYy5Db21tYW5kKCJtb3VudCIsIGFyZ3MuLi4pCgl9CgoJb3V0LCBlcnIgOj0gY21kLkNvbWJpbmVk"
    "T3V0cHV0KCkKCWlmIGVyciAhPSBuaWwgewoJCXJldHVybiBmbXQuRXJyb3JmKCJtb3VudCAlcyAtPiAlcyBmYWlsZWQ6ICV2OiAl"
    "cyIsIHNyYywgbS5Mb2NhbCwgZXJyLCBzdHJpbmdzLlRyaW1TcGFjZShzdHJpbmcob3V0KSkpCgl9Cglsb2dmKCJtb3VudGVkICVz"
    "IC0+ICVzIiwgc3JjLCBtLkxvY2FsKQoJcmV0dXJuIG5pbAp9CgpmdW5jIG9uZXNob3QoKSBpbnQgewoJcmVxdWlyZVJvb3QoKQoJ"
    "YywgZXJyIDo9IGxvYWRDb25maWcoKQoJaWYgZXJyICE9IG5pbCB7CgkJbG9nZigiZmF0YWw6ICV2IiwgZXJyKQoJCXJldHVybiAy"
    "Cgl9CgllbnN1cmVEZXBzKGMpCgoJYXR0ZW1wdHMgOj0gYy5SZXRyeUF0dGVtcHRzCglpZiBhdHRlbXB0cyA8IDEgewoJCWF0dGVt"
    "cHRzID0gMQoJfQoJZGVsYXkgOj0gdGltZS5EdXJhdGlvbihjLlJldHJ5RGVsYXlTZWMpICogdGltZS5TZWNvbmQKCWlmIGRlbGF5"
    "IDw9IDAgewoJCWRlbGF5ID0gNSAqIHRpbWUuU2Vjb25kCgl9CgoJcGVuZGluZyA6PSBhcHBlbmQoW11Nb3VudFNwZWN7fSwgYy5N"
    "b3VudHMuLi4pCgl2YXIgbGFzdEVyciBlcnJvcgoJZm9yIGF0dGVtcHQgOj0gMTsgYXR0ZW1wdCA8PSBhdHRlbXB0cyAmJiBsZW4o"
    "cGVuZGluZykgPiAwOyBhdHRlbXB0KysgewoJCXZhciBzdGlsbFBlbmRpbmcgW11Nb3VudFNwZWMKCQlmb3IgXywgbSA6PSByYW5n"
    "ZSBwZW5kaW5nIHsKCQkJaWYgZXJyIDo9IG1vdW50T25lKGMsIG0pOyBlcnIgIT0gbmlsIHsKCQkJCWxvZ2YoImF0dGVtcHQgJWQv"
    "JWQ6ICV2IiwgYXR0ZW1wdCwgYXR0ZW1wdHMsIGVycikKCQkJCWxhc3RFcnIgPSBlcnIKCQkJCXN0aWxsUGVuZGluZyA9IGFwcGVu"
    "ZChzdGlsbFBlbmRpbmcsIG0pCgkJCX0KCQl9CgkJcGVuZGluZyA9IHN0aWxsUGVuZGluZwoJCWlmIGxlbihwZW5kaW5nKSA+IDAg"
    "JiYgYXR0ZW1wdCA8IGF0dGVtcHRzIHsKCQkJLy8gbGluZWFyLWlzaCBiYWNrb2ZmLCBjYXBwZWQKCQkJZCA6PSBkZWxheSAqIHRp"
    "bWUuRHVyYXRpb24oYXR0ZW1wdCkKCQkJaWYgZCA+IDYwKnRpbWUuU2Vjb25kIHsKCQkJCWQgPSA2MCAqIHRpbWUuU2Vjb25kCgkJ"
    "CX0KCQkJbG9nZigiJWQgbW91bnQocykgcGVuZGluZywgcmV0cnlpbmcgaW4gJXMgLi4uIiwgbGVuKHBlbmRpbmcpLCBkKQoJCQl0"
    "aW1lLlNsZWVwKGQpCgkJfQoJfQoKCWlmIGxlbihwZW5kaW5nKSA+IDAgewoJCWxvZ2YoImdpdmluZyB1cDogJWQgbW91bnQocykg"
    "c3RpbGwgbm90IG1vdW50ZWQgKGxhc3QgZXJyb3I6ICV2KSIsIGxlbihwZW5kaW5nKSwgbGFzdEVycikKCQlyZXR1cm4gMSAvLyBu"
    "b24temVybywgYnV0IGJvb3QgaXMgdW5hZmZlY3RlZCBiZWNhdXNlIG5vdGhpbmcgZGVwZW5kcyBvbiB0aGlzIHVuaXQKCX0KCWxv"
    "Z2YoImFsbCBtb3VudHMgdXAiKQoJcmV0dXJuIDAKfQoKZnVuYyBzdGF0dXMoKSBpbnQgewoJYywgZXJyIDo9IGxvYWRDb25maWco"
    "KQoJaWYgZXJyICE9IG5pbCB7CgkJbG9nZigiZmF0YWw6ICV2IiwgZXJyKQoJCXJldHVybiAyCgl9Cglmb3IgXywgbSA6PSByYW5n"
    "ZSBjLk1vdW50cyB7CgkJc3RhdGUgOj0gIk5PVCBtb3VudGVkIgoJCWlmIGlzTW91bnRlZChtLkxvY2FsKSB7CgkJCXN0YXRlID0g"
    "Im1vdW50ZWQiCgkJfQoJCWZtdC5QcmludGYoIiUtMzBzICVzXG4iLCBtLkxvY2FsLCBzdGF0ZSkKCX0KCXJldHVybiAwCn0KCmZ1"
    "bmMgc2VsZnRlc3QoKSBpbnQgewoJYywgZXJyIDo9IGxvYWRDb25maWcoKQoJaWYgZXJyICE9IG5pbCB7CgkJbG9nZigic2VsZnRl"
    "c3QgRkFJTEVEOiAldiIsIGVycikKCQlyZXR1cm4gMgoJfQoJbWFza2VkIDo9ICI/IgoJaWYgbGVuKGMuSG9zdCkgPiAwIHsKCQlt"
    "YXNrZWQgPSBzdHJpbmcoYy5Ib3N0WzBdKSArICIqKioiCgl9CglmbXQuUHJpbnRmKCJjb25maWcgZGVjcnlwdGVkIE9LOiBwcm90"
    "b2NvbD0lcyBob3N0PSVzIG1vdW50cz0lZFxuIiwgYy5Qcm90b2NvbCwgbWFza2VkLCBsZW4oYy5Nb3VudHMpKQoJcmV0dXJuIDAK"
    "fQoKY29uc3QgdW5pdFRlbXBsYXRlID0gYFtVbml0XQpEZXNjcmlwdGlvbj1OQVMgYXV0byBtb3VudCAobmFzLWVucC1tb3VudCkK"
    "QWZ0ZXI9bmV0d29yay1vbmxpbmUudGFyZ2V0CldhbnRzPW5ldHdvcmstb25saW5lLnRhcmdldAojIEludGVudGlvbmFsbHkgbm8g"
    "UmVxdWlyZXMgZnJvbSBvdGhlciB1bml0cyAtPiBmYWlsdXJlcyBuZXZlciBibG9jayBib290LgpTdGFydExpbWl0SW50ZXJ2YWxT"
    "ZWM9MAoKW1NlcnZpY2VdClR5cGU9b25lc2hvdApSZW1haW5BZnRlckV4aXQ9eWVzCkV4ZWNTdGFydD0lcy8lcyAtLW9uZXNob3QK"
    "IyBCb3VuZGVkIHNvIGEgZGVhZCBOQVMgY2FuIG5ldmVyIGhhbmcgYm9vdDsgcmV0cmllcyBoYXBwZW4gaW5zaWRlIHRoaXMgYnVk"
    "Z2V0LgpUaW1lb3V0U3RhcnRTZWM9MTUwCgpbSW5zdGFsbF0KV2FudGVkQnk9bXVsdGktdXNlci50YXJnZXQKYAoKZnVuYyBpbnN0"
    "YWxsU2VydmljZSgpIGludCB7CglyZXF1aXJlUm9vdCgpCglpZiBfLCBlcnIgOj0gbG9hZENvbmZpZygpOyBlcnIgIT0gbmlsIHsK"
    "CQlsb2dmKCJyZWZ1c2luZyB0byBpbnN0YWxsOiAldiIsIGVycikKCQlyZXR1cm4gMgoJfQoJaWYgZXJyIDo9IG9zLk1rZGlyQWxs"
    "KGluc3RhbGxEaXIsIDBvNzAwKTsgZXJyICE9IG5pbCB7CgkJbG9nZigiZmF0YWw6ICV2IiwgZXJyKQoJCXJldHVybiAyCgl9Cgkv"
    "LyBjb3B5IHNlbGYgaW50byBpbnN0YWxsRGlyIGlmIHJ1bm5pbmcgZnJvbSBlbHNld2hlcmUKCXNlbGYsIF8gOj0gb3MuRXhlY3V0"
    "YWJsZSgpCgl0YXJnZXQgOj0gZmlsZXBhdGguSm9pbihpbnN0YWxsRGlyLCBiaW5OYW1lKQoJaWYgYWJzLCBfIDo9IGZpbGVwYXRo"
    "LkFicyhzZWxmKTsgYWJzICE9IHRhcmdldCB7CgkJZGF0YSwgZXJyIDo9IG9zLlJlYWRGaWxlKHNlbGYpCgkJaWYgZXJyICE9IG5p"
    "bCB7CgkJCWxvZ2YoImZhdGFsOiByZWFkIHNlbGY6ICV2IiwgZXJyKQoJCQlyZXR1cm4gMgoJCX0KCQlpZiBlcnIgOj0gb3MuV3Jp"
    "dGVGaWxlKHRhcmdldCwgZGF0YSwgMG83MDApOyBlcnIgIT0gbmlsIHsKCQkJbG9nZigiZmF0YWw6IHdyaXRlICVzOiAldiIsIHRh"
    "cmdldCwgZXJyKQoJCQlyZXR1cm4gMgoJCX0KCQlsb2dmKCJpbnN0YWxsZWQgYmluYXJ5IHRvICVzIiwgdGFyZ2V0KQoJfQoJdW5p"
    "dCA6PSBmbXQuU3ByaW50Zih1bml0VGVtcGxhdGUsIGluc3RhbGxEaXIsIGJpbk5hbWUpCgl1bml0UGF0aCA6PSAiL2V0Yy9zeXN0"
    "ZW1kL3N5c3RlbS8iICsgc2VydmljZU5hbWUKCWlmIGVyciA6PSBvcy5Xcml0ZUZpbGUodW5pdFBhdGgsIFtdYnl0ZSh1bml0KSwg"
    "MG82NDQpOyBlcnIgIT0gbmlsIHsKCQlsb2dmKCJmYXRhbDogd3JpdGUgdW5pdDogJXYiLCBlcnIpCgkJcmV0dXJuIDIKCX0KCWxv"
    "Z2YoIndyb3RlICVzIiwgdW5pdFBhdGgpCglmb3IgXywgYXJncyA6PSByYW5nZSBbXVtdc3RyaW5newoJCXsiZGFlbW9uLXJlbG9h"
    "ZCJ9LAoJCXsiZW5hYmxlIiwgc2VydmljZU5hbWV9LAoJCXsic3RhcnQiLCBzZXJ2aWNlTmFtZX0sCgl9IHsKCQlvdXQsIGVyciA6"
    "PSBleGVjLkNvbW1hbmQoInN5c3RlbWN0bCIsIGFyZ3MuLi4pLkNvbWJpbmVkT3V0cHV0KCkKCQlpZiBlcnIgIT0gbmlsIHsKCQkJ"
    "bG9nZigid2Fybjogc3lzdGVtY3RsICV2OiAldjogJXMiLCBhcmdzLCBlcnIsIHN0cmluZ3MuVHJpbVNwYWNlKHN0cmluZyhvdXQp"
    "KSkKCQl9Cgl9Cglsb2dmKCJzZXJ2aWNlIGluc3RhbGxlZCBhbmQgc3RhcnRlZC4gQ2hlY2s6IHN5c3RlbWN0bCBzdGF0dXMgJXMi"
    "LCBzZXJ2aWNlTmFtZSkKCXJldHVybiAwCn0KCmZ1bmMgdW5pbnN0YWxsKCkgaW50IHsKCXJlcXVpcmVSb290KCkKCWV4ZWMuQ29t"
    "bWFuZCgic3lzdGVtY3RsIiwgImRpc2FibGUiLCAiLS1ub3ciLCBzZXJ2aWNlTmFtZSkuUnVuKCkKCW9zLlJlbW92ZSgiL2V0Yy9z"
    "eXN0ZW1kL3N5c3RlbS8iICsgc2VydmljZU5hbWUpCglleGVjLkNvbW1hbmQoInN5c3RlbWN0bCIsICJkYWVtb24tcmVsb2FkIiku"
    "UnVuKCkKCWlmIGMsIGVyciA6PSBsb2FkQ29uZmlnKCk7IGVyciA9PSBuaWwgewoJCWZvciBfLCBtIDo9IHJhbmdlIGMuTW91bnRz"
    "IHsKCQkJaWYgaXNNb3VudGVkKG0uTG9jYWwpIHsKCQkJCW91dCwgZXJyIDo9IGV4ZWMuQ29tbWFuZCgidW1vdW50IiwgbS5Mb2Nh"
    "bCkuQ29tYmluZWRPdXRwdXQoKQoJCQkJaWYgZXJyICE9IG5pbCB7CgkJCQkJbG9nZigid2FybjogdW1vdW50ICVzOiAldjogJXMi"
    "LCBtLkxvY2FsLCBlcnIsIHN0cmluZ3MuVHJpbVNwYWNlKHN0cmluZyhvdXQpKSkKCQkJCX0gZWxzZSB7CgkJCQkJbG9nZigidW5t"
    "b3VudGVkICVzIiwgbS5Mb2NhbCkKCQkJCX0KCQkJfQoJCX0KCX0KCWxvZ2YoInVuaW5zdGFsbGVkIikKCXJldHVybiAwCn0KCmZ1"
    "bmMgdXNhZ2UoKSB7CglmbXQuUHJpbnRsbihgbmFzLWVucC1tb3VudAogIChubyBhcmdzKSAvIC0tb25lc2hvdCAgIG1vdW50IGFs"
    "bCBzaGFyZXMgb25jZSAod2l0aCBpbnRlcm5hbCByZXRyaWVzKQogIC0taW5zdGFsbC1zZXJ2aWNlICAgICAgIGluc3RhbGwgJiBl"
    "bmFibGUgc3lzdGVtZCBib290IHNlcnZpY2UKICAtLXVuaW5zdGFsbCAgICAgICAgICAgICBzdG9wIHNlcnZpY2UsIHJlbW92ZSB1"
    "bml0LCB1bm1vdW50IHNoYXJlcwogIC0tc3RhdHVzICAgICAgICAgICAgICAgIHNob3cgbW91bnQgc3RhdHVzCiAgLS1zZWxmdGVz"
    "dCAgICAgICAgICAgICAgdmVyaWZ5IGVtYmVkZGVkIGNvbmZpZyBkZWNyeXB0cyAobm8gc2VjcmV0cyBwcmludGVkKWApCn0KCmZ1"
    "bmMgbWFpbigpIHsKCW1vZGUgOj0gIi0tb25lc2hvdCIKCWlmIGxlbihvcy5BcmdzKSA+IDEgewoJCW1vZGUgPSBvcy5BcmdzWzFd"
    "Cgl9Cglzd2l0Y2ggbW9kZSB7CgljYXNlICItLW9uZXNob3QiLCAiIjoKCQlvcy5FeGl0KG9uZXNob3QoKSkKCWNhc2UgIi0taW5z"
    "dGFsbC1zZXJ2aWNlIjoKCQlvcy5FeGl0KGluc3RhbGxTZXJ2aWNlKCkpCgljYXNlICItLXVuaW5zdGFsbCI6CgkJb3MuRXhpdCh1"
    "bmluc3RhbGwoKSkKCWNhc2UgIi0tc3RhdHVzIjoKCQlvcy5FeGl0KHN0YXR1cygpKQoJY2FzZSAiLS1zZWxmdGVzdCI6CgkJb3Mu"
    "RXhpdChzZWxmdGVzdCgpKQoJY2FzZSAiLWgiLCAiLS1oZWxwIiwgImhlbHAiOgoJCXVzYWdlKCkKCWRlZmF1bHQ6CgkJdXNhZ2Uo"
    "KQoJCW9zLkV4aXQoMikKCX0KfQo=")

def go_template() -> str:
    return base64.b64decode("".join(GO_TEMPLATE_B64)).decode()


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
    return (go_template()
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
            f"  chmod +x /root/nas-enp-mount/{name}\n"
            f"  /root/nas-enp-mount/{name} --selftest         # 自检\n"
            f"  /root/nas-enp-mount/{name} --install-service  # 开机自启\n"
            "\n提醒：请使用专用、最小权限、可随时吊销的 NAS 账号。"
        )
    return (
        "Deploy on each Linux client (as root):\n"
        "  mkdir -p /root/nas-enp-mount\n"
        f"  cp {name} /root/nas-enp-mount/\n"
        f"  chmod +x /root/nas-enp-mount/{name}\n"
        f"  /root/nas-enp-mount/{name} --selftest         # sanity check\n"
        f"  /root/nas-enp-mount/{name} --install-service  # enable at boot\n"
        "\nReminder: use a dedicated, least-privilege, revocable NAS account."
    )

# ------------------------------------------------------------------ build
def build(src: str, arches, out_base: str, do_build: bool):
    out_base = os.path.abspath(out_base)
    workdir = tempfile.mkdtemp(prefix="nasenp-")
    with open(os.path.join(workdir, "main.go"), "w") as f:
        f.write(src)

    if not do_build:
        dst = out_base + ".go"
        shutil.copy(os.path.join(workdir, "main.go"), dst)
        return {"mode": "source", "path": dst}

    if not shutil.which("go"):
        raise RuntimeError("Go toolchain not found. Install Go, or use --no-build / "
                            "the \"emit Go source only\" option.")

    subprocess.run(["go", "mod", "init", "nasenpmount"], cwd=workdir,
                   check=True, capture_output=True)

    outputs = []
    for arch in arches:
        out = out_base if len(arches) == 1 else f"{out_base}-{arch}"
        env = dict(os.environ, GOOS="linux", GOARCH=arch,
                   CGO_ENABLED="0", GOFLAGS="-mod=mod")
        r = subprocess.run(
            ["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", out, "."],
            cwd=workdir, env=env, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"build failed for {arch}:\n{r.stderr}")
        os.chmod(out, 0o700)
        outputs.append(out)
    return {"mode": "binary", "paths": outputs}

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
        "arch": "Target arch(es):",
        "emit_source_only": "Emit Go source only (no Go toolchain needed here)",
        "out_path": "Output path:",
        "save_config": "Save config to:",
        "save_config_placeholder": "(optional) also save config JSON to ...",
        "generate": "Generate",
        "invalid_config_title": "Invalid configuration",
        "build_error_title": "Build failed",
        "done_title": "Done",
        "close": "Close",
        "script_written": "Client binary written to: {path}\n\n",
        "source_written": "Go source written to: {path}\n\nCompile on any Linux box with:\n"
                           "  cd <dir> && go mod init nasenpmount && "
                           "CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o nas-enp-mount .\n",
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
        "arch": "目标架构：",
        "emit_source_only": "仅导出 Go 源码（本机无需 Go 工具链）",
        "out_path": "输出路径：",
        "save_config": "保存配置到：",
        "save_config_placeholder": "（可选）同时保存配置 JSON 到……",
        "generate": "生成",
        "invalid_config_title": "配置无效",
        "build_error_title": "构建失败",
        "done_title": "完成",
        "close": "关闭",
        "script_written": "客户端二进制已写入：{path}\n\n",
        "source_written": "Go 源码已写入：{path}\n\n可在任意 Linux 机器上编译：\n"
                           "  cd <dir> && go mod init nasenpmount && "
                           "CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o nas-enp-mount .\n",
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

            self.arch = QLineEdit("amd64")
            self.form2.addRow(" ", self.arch)

            self.emit_source_only = QCheckBox()
            self.form2.addRow(self.emit_source_only)

            self.out_path = QLineEdit("nas-enp-mount")
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
            self.form2.labelForField(self.arch).setText(s["arch"])
            self.emit_source_only.setText(s["emit_source_only"])
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

            out_path = self.out_path.text().strip() or "nas-enp-mount"
            save_path = self.save_config_path.text().strip()
            if save_path:
                with open(save_path, "w") as f:
                    json.dump(cfg, f, indent=2)
                os.chmod(save_path, 0o600)

            blob = encrypt_config(cfg)
            src = fill_template(blob)
            arches = [a.strip() for a in self.arch.text().split(",") if a.strip()] or ["amd64"]
            try:
                result = build(src, arches, out_path, not self.emit_source_only.isChecked())
            except RuntimeError as e:
                QMessageBox.critical(self, s["build_error_title"], str(e))
                return

            if result["mode"] == "source":
                body = s["source_written"].format(path=result["path"])
            else:
                body = s["script_written"].format(path=result["paths"][0]) + \
                    deploy_instructions(result["paths"][0], lang=self.lang)

            dlg = QDialog(self)
            dlg.setWindowTitle(s["done_title"])
            layout = QVBoxLayout(dlg)
            text = QPlainTextEdit(body)
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
    ap = argparse.ArgumentParser(description="Generate an encrypted NAS auto-mount client binary.")
    ap.add_argument("--config", help="JSON config file (skips interactive prompts / GUI)")
    ap.add_argument("--cli", action="store_true", help="use terminal prompts instead of the GUI")
    ap.add_argument("--arch", default="amd64",
                    help="comma-separated Go arches: amd64,arm64,arm,386 (default amd64)")
    ap.add_argument("--out", default="nas-enp-mount", help="output binary path/name")
    ap.add_argument("--no-build", action="store_true", help="emit Go source instead of compiling")
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
    arches = [a.strip() for a in args.arch.split(",") if a.strip()]
    try:
        result = build(src, arches, args.out, not args.no_build)
    except RuntimeError as e:
        sys.exit(str(e))

    if result["mode"] == "source":
        print(f"\n[emit] Go source written to: {result['path']}")
        print("Compile on any Linux box with:")
        print(f"  cd <dir> && go mod init nasenpmount && "
              f"CGO_ENABLED=0 go build -trimpath -ldflags '-s -w' -o nas-enp-mount .")
    else:
        for p in result["paths"]:
            print(f"[ok] built: {p}")
        print(f"\n{deploy_instructions(result['paths'][0])}")

if __name__ == "__main__":
    main()
