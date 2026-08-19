# Third-party notices

The **source** in this repository is Apache-2.0 (see `LICENSE`) and contains no
third-party code. This file exists because the **binaries** do: the `.deb` and
`.exe` attached to each GitHub Release are PyInstaller onefile bundles
(`packaging/nas-enp-gen.spec`, built by `.github/workflows/release-installers.yml`),
and they embed the components below. Anyone redistributing those binaries
carries these obligations too.

Running the generator from source with your own `pip install -r requirements.txt`
does not create a combined distribution, so only the upstream licenses of the
packages you installed apply — this file is still the accurate list of what they
are.

## Components bundled in the released `.deb` / `.exe`

| Component | Version | License | Upstream |
|---|---|---|---|
| PySide6 (Qt for Python) | 6.11.1 (pinned in `requirements.txt`) | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only — used here under **LGPL-3.0** | https://pypi.org/project/PySide6/ · https://doc.qt.io/qtforpython/ |
| shiboken6 (PySide6's binding runtime, installed as its dependency) | 6.11.1 | LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only — used here under **LGPL-3.0** | https://pypi.org/project/shiboken6/ |
| Qt 6 libraries shipped inside the PySide6 wheel (`QtCore`, `QtGui`, `QtWidgets`, the `xcb`/`windows` platform plugins, …) | as shipped with PySide6 6.11.1 | **LGPL-3.0** | https://www.qt.io/ · sources: https://download.qt.io/official_releases/qt/ |
| `cryptography` | 3.4.8 (pinned in `requirements.txt`) | Apache-2.0 OR BSD-3-Clause | https://pypi.org/project/cryptography/ |
| OpenSSL, statically linked into `cryptography`'s `_openssl` extension by its binary wheels | OpenSSL 1.1.1 series, as shipped in the `cryptography` 3.4.8 wheels | **OpenSSL License AND SSLeay License** (BSD-style, attribution required) | https://www.openssl.org/source/license-openssl-ssleay.txt |
| CPython runtime embedded by PyInstaller | 3.11 (the version `actions/setup-python` installs in CI) | PSF License Agreement (Python-2.0) | https://docs.python.org/3/license.html |
| PyInstaller bootloader linked into the onefile executable | whatever `pip install pyinstaller` resolves at build time (unpinned) | GPL-2.0-or-later **with the PyInstaller bootloader exception**, which explicitly permits bundling applications under any license | https://pyinstaller.org/en/stable/license.html |

Reproduce this list for a specific build with
`pip install -r requirements.txt && pip freeze`, plus
`python -c "from cryptography.hazmat.backends.openssl.backend import backend; print(backend.openssl_version_text())"`
in the same environment. If `cryptography` is installed from source against a
system OpenSSL 3.x instead of from a wheel, the OpenSSL row becomes Apache-2.0
and nothing is statically linked.

## LGPL-3.0 compliance for the released binaries

PySide6 and the Qt 6 libraries it ships are used under LGPL-3.0. The released
`.deb`/`.exe` are therefore *Combined Works* under LGPL-3.0 §4, which requires:

1. **Notice.** Stated here and in `README.md`: these binaries use PySide6/Qt,
   which are covered by the GNU LGPL version 3.
2. **A copy of the GPL and LGPL.** Both are published at
   https://www.gnu.org/licenses/gpl-3.0.txt and
   https://www.gnu.org/licenses/lgpl-3.0.txt, and ship inside the PySide6 wheel
   that is bundled into the binary.
3. **The ability to relink against a modified PySide6/Qt.** Satisfied by
   §4(d)(0): the complete Corresponding Application Code is public — the whole
   application is a single Apache-2.0 Python file (`nas-enp-gen.py`) in this
   repository, the exact build recipe is `packaging/nas-enp-gen.spec` plus
   `packaging/build-deb.sh`, and the dependency versions are pinned in
   `requirements.txt`. Anyone can install a modified PySide6/Qt and rebuild an
   equivalent binary from those files, with no material from this project
   withheld.
4. **No additional restrictions.** Apache-2.0 imposes none on the LGPL portions.

Qt's own sources for the bundled version are available from
https://download.qt.io/official_releases/qt/ and, for the PySide6/shiboken6
layer, from https://pypi.org/project/PySide6/ (sdist) — this project modifies
neither.

## Attribution required by the OpenSSL / SSLeay license

When redistributing a binary built from `cryptography`'s wheels:

> This product includes software developed by the OpenSSL Project for use in
> the OpenSSL Toolkit (http://www.openssl.org/)
>
> This product includes cryptographic software written by Eric Young
> (eay@cryptsoft.com)

## Not bundled

The generated client script (`nas-enp-mount.py`) contains no third-party code:
it is pure standard-library Python plus the `cryptography` package the client
machine installs itself. The `.deb`'s `Depends:` list names ordinary
Debian/Ubuntu system libraries, which apt installs from the distribution — they
are not redistributed by this project.
