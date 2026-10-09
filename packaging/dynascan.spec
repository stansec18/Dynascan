# PyInstaller spec - builds dist/Dynascan/Dynascan.exe (windowed GUI, one-folder layout).
# Run on Windows:  pyinstaller packaging/dynascan.spec --noconfirm
from PyInstaller.utils.hooks import collect_submodules

hidden = collect_submodules("dynascan") + ["bs4", "yaml", "jinja2", "httpx", "h11", "anyio"]

a = Analysis(
    ["gui_entry.py"],
    pathex=[".."],
    datas=[("../dynascan/report/templates/*.html", "dynascan/report/templates")],
    hiddenimports=hidden,
    excludes=["tkinter", "PySide6.QtWebEngineCore", "PySide6.Qt3DCore"],
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="Dynascan",
    console=False,          # GUI app: no console window
    icon=None,              # set to an .ico path to brand the executable
)
coll = COLLECT(exe, a.binaries, a.datas, name="Dynascan")
