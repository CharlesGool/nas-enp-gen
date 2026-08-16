# PyInstaller spec for the nas-enp-gen generator (GUI + CLI, single file).
# Build: pyinstaller packaging/nas-enp-gen.spec   (run from anywhere; paths
# below are resolved relative to this spec file's own location via SPECPATH,
# which PyInstaller injects into the spec's exec namespace at build time.)
# Output: dist/nas-enp-gen (Linux) or dist/nas-enp-gen.exe (Windows)
import os

# The generator's GUI only uses QtWidgets/QtCore/QtGui (a plain form with
# QLineEdit/QComboBox/QSpinBox/etc). PyInstaller's built-in PySide6 hooks
# already pull in the platform plugin each OS needs. Explicitly excluding
# the unused Qt subsystems keeps the bundle from ballooning to 250MB+ with
# QML, multimedia/codec, SQL-driver, Bluetooth, and NFC binaries we never
# import or ship.
EXCLUDE_QT_MODULES = [
    "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuick3D",
    "PySide6.QtQuickWidgets", "PySide6.QtMultimedia",
    "PySide6.QtMultimediaWidgets", "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
    "PySide6.QtPdf", "PySide6.QtPdfWidgets", "PySide6.QtSql",
    "PySide6.QtNfc", "PySide6.QtBluetooth", "PySide6.QtSensors",
    "PySide6.QtPositioning", "PySide6.QtSpatialAudio",
    "PySide6.QtTextToSpeech", "PySide6.QtNetworkAuth",
    "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtRemoteObjects", "PySide6.QtSerialPort",
    "PySide6.QtSerialBus", "PySide6.Qt3DCore", "PySide6.Qt3DRender",
    "PySide6.Qt3DInput", "PySide6.Qt3DLogic", "PySide6.Qt3DAnimation",
    "PySide6.Qt3DExtras", "PySide6.QtWayland",
]

a = Analysis(
    [os.path.join(SPECPATH, "..", "nas-enp-gen.py")],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDE_QT_MODULES,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="nas-enp-gen",
    debug=False,
    strip=False,
    upx=False,
    console=True,
    onefile=True,
)
