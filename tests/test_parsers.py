import json
from datetime import UTC, datetime
from pathlib import Path

from sysscan.collectors.appx import parse_packages
from sysscan.collectors.devpkgs import (
    interpreter_label,
    parse_choco_lib,
    parse_extensions,
    parse_npm_ls,
    parse_pip_inspect,
    parse_scoop_apps,
)
from sysscan.collectors.drivers import group_drivers, parse_setupapi
from sysscan.collectors.history import (
    classify_update_title,
    parse_msi_events,
    parse_reliability,
    parse_service_events,
    parse_wu_history,
)
from sysscan.collectors.uninstall_registry import parse_entry, pick_install_time
from sysscan.models import Action, Category, TimeConfidence

FIX = Path(__file__).parent / "fixtures"
SINCE = datetime(2026, 9, 1, tzinfo=UTC)
UNTIL = datetime(2026, 9, 30, tzinfo=UTC)


# ----------------------------------------------------------------------------- registry

def test_parse_entry_skips_components_and_patches():
    assert parse_entry({"DisplayName": "X", "SystemComponent": 1}, "k", "p", "machine", None) is None
    assert parse_entry({"DisplayName": "X", "ParentKeyName": "Office"}, "k", "p", "machine", None) is None
    assert parse_entry({}, "k", "p", "machine", None) is None


def test_parse_entry_fields():
    it = parse_entry({"DisplayName": "Blender", "DisplayVersion": "4.2.1", "Publisher": "Blender Foundation",
                      "InstallDate": "20260924", "WindowsInstaller": 1}, "{GUID}", "reg:HKLM64", "machine", None)
    assert it.key == "reg:HKLM64:{GUID}" and it.version == "4.2.1" and it.extra["msi"]
    assert it.time_confidence == TimeConfidence.DAY


def test_pick_install_time_prefers_same_day_write_time():
    lw = datetime(2026, 9, 24, 16, 0, tzinfo=UTC)
    t, conf = pick_install_time("20260924", lw)
    assert (t, conf) == (lw, TimeConfidence.FILE)
    t, conf = pick_install_time(None, None)
    assert t is None and conf == TimeConfidence.UNKNOWN


# ----------------------------------------------------------------------------- event history

def test_reliability_msi_and_wu():
    rows = [
        {"t": "2026-09-24T21:16:00Z", "id": 11707, "source": "MsiInstaller", "product": "Blender",
         "msg": "Product: Blender -- Installation completed successfully."},
        {"t": "2026-09-20T03:05:00Z", "id": 19, "source": "Microsoft-Windows-WindowsUpdateClient",
         "product": "2026-09 Cumulative Update for Windows 11 (KB5065426)", "msg": ""},
        {"t": "2026-09-20T03:05:00Z", "id": 1000, "source": "MsiInstaller", "product": "ignored", "msg": ""},
    ]
    ev = parse_reliability(rows)
    assert [e.action for e in ev] == [Action.INSTALLED, Action.UPDATED]
    assert ev[1].category == Category.WINDOWS_UPDATE and ev[1].version_to == "KB5065426"


def test_msi_events_use_properties_and_skip_failures():
    rows = [
        {"t": "2026-09-21T09:40:00Z", "id": 1033, "props": ["Tool", "1.3.0", "1033", "0", "Contoso"], "msg": ""},
        {"t": "2026-09-21T09:41:00Z", "id": 1033, "props": ["Broken", "1.0", "1033", "1603", "Contoso"], "msg": ""},
        {"t": "2026-09-22T09:40:00Z", "id": 11724, "props": ["Product: Old Tool -- Removal completed successfully."],
         "msg": "Product: Old Tool -- Removal completed successfully."},
    ]
    ev = parse_msi_events(rows)
    assert [(e.name, e.action) for e in ev] == [("Tool", Action.INSTALLED), ("Old Tool", Action.UNINSTALLED)]
    assert ev[0].publisher == "Contoso" and ev[0].version_to == "1.3.0"


def test_service_events_split_kernel_drivers():
    rows = [{"t": "2026-09-22T10:00:00Z", "props": ["FooSvc", "C:\\foo.exe", "user mode service"]},
            {"t": "2026-09-22T10:00:00Z", "props": ["foodrv", "\\SystemRoot\\foo.sys", "kernel mode driver"]}]
    a, b = parse_service_events(rows)
    assert a.category == Category.DESKTOP_APP and b.category == Category.DRIVER


def test_wu_history_filters_and_classifies():
    rows = [
        {"t": "2026-09-10T03:00:00Z", "title": "Intel - System - 2409.5.63.0", "op": 1, "rc": 2},
        {"t": "2026-09-10T03:00:00Z", "title": "Failed thing (KB1)", "op": 1, "rc": 4},
        {"t": "2025-01-01T03:00:00Z", "title": "Too old (KB5000000)", "op": 1, "rc": 2},
        {"t": "2026-09-11T03:00:00Z", "title": "Update (KB5012345)", "op": 2, "rc": 2, "client": "wusa"},
    ]
    ev = parse_wu_history(rows, SINCE, UNTIL)
    assert len(ev) == 2
    assert ev[0].category == Category.DRIVER and ev[0].name == "Intel - System" and ev[0].version_to == "2409.5.63.0"
    assert ev[1].action == Action.UNINSTALLED and "wusa" in ev[1].detail


def test_classify_update_title():
    assert classify_update_title("Realtek - Net - 10.68.815.2024")[0] == Category.DRIVER
    assert classify_update_title("2026-09 Cumulative Update (KB5065426)") == (
        Category.WINDOWS_UPDATE, "2026-09 Cumulative Update (KB5065426)", "KB5065426")


# ----------------------------------------------------------------------------- drivers

def test_setupapi_log_windows11_format():
    names = {r"PCI\VEN_14C3&DEV_0616&SUBSYS_0000&REV_00\4&AAAA&0&0012":
             ("MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter", "MediaTek, Inc.")}
    with (FIX / "setupapi.dev.log").open() as fh:
        ev = parse_setupapi(fh, SINCE, UNTIL, names)
    by_name = {e.name: e for e in ev}

    wifi = by_name["MediaTek, Inc. driver for MediaTek Wi-Fi 6E MT7922 (RZ616) 160MHz PCIe Adapter"]
    assert wifi.action == Action.UPDATED and wifi.version_to == "3.5.0.1200"  # the *selected* node
    assert "oem141.inf" in wifi.detail

    inbox = next(e for e in ev if e.name.startswith("Windows built-in driver for"))
    assert inbox.action == Action.INSTALLED and inbox.version_to == "10.0.26100.8521"

    pkg = by_name["Contoso Inc driver package gwdrv.inf"]
    assert pkg.version_to == "2.1.835.0" and "oem41.inf" in pkg.detail

    legacy = next(e for e in ev if "Realtek PCIe GbE" in e.name)  # older Windows 10 layout still parses
    assert legacy.version_to == "10.68.0.0"

    assert not any("prnms006" in e.name for e in ev)  # "already imported" no-op
    assert not any("broken" in e.detail for e in ev)  # failed install
    assert not any("old.inf" in e.detail for e in ev)  # outside the period
    assert len(ev) == 4


def test_store_updates_in_windows_update_history():
    cat, name, _ = classify_update_title("9NRZT3Q9R3DL-Microsoft.WindowsAppRuntime.2")
    assert cat == Category.STORE_APP and name == "Windows App Runtime 2"
    assert classify_update_title("ApplicationSet-9PB2MZ1ZMB1S-AppleInc.iTunes")[0] == Category.STORE_APP


def test_group_drivers():
    rows = [{"device": f"Intel dev {i}", "cls": "System", "ver": "1.0", "provider": "Intel", "id": f"PCI\\X{i}"}
            for i in range(6)]
    rows.append({"device": "GPU", "cls": "Display", "ver": "32.0", "provider": "NVIDIA"})
    rows.append({"device": "junk", "cls": "", "ver": "2:10.0,2:6.3", "provider": ""})  # WMI noise
    items = {i.name: i for i in group_drivers(rows)}
    assert set(items) == {"Intel system devices driver", "NVIDIA graphics driver"}
    assert "and 2 more" in items["Intel system devices driver"].description
    assert items["Intel system devices driver"].extra["device_ids"]["PCI\\X0"] == "Intel dev 0"


# ----------------------------------------------------------------------------- appx

def test_appx_parse():
    rows = [{"full": "Microsoft.WindowsCalculator_11.2408.12.0_x64__8wekyb3d8bbwe", "ver": "11.2408.12.0",
             "pub": "CN=Microsoft Corporation, O=Microsoft Corporation, C=US", "fw": False,
             "created": "2026-09-20T03:12:00Z", "loc": None}]
    (it,) = parse_packages(rows)
    assert it.key == "appx:Microsoft.WindowsCalculator_x64_8wekyb3d8bbwe"
    assert it.name == "Windows Calculator" and it.publisher == "Microsoft Corporation"


# ----------------------------------------------------------------------------- dev packages

def test_pip_inspect(tmp_path):
    meta = tmp_path / "httpx-0.27.2.dist-info"
    meta.mkdir()
    data = {"installed": [{"metadata": {"name": "httpx", "version": "0.27.2", "summary": "HTTP client"},
                           "metadata_location": str(meta)}]}
    (it,) = parse_pip_inspect(data, "Python312")
    assert it.key == "pip:Python312:httpx" and it.description == "HTTP client" and it.install_time


def test_interpreter_label():
    assert interpreter_label(r"C:\Python312\python.exe".replace("\\", "/")) == "Python312"


def test_npm_ls():
    (it,) = parse_npm_ls({"dependencies": {"pnpm": {"version": "9.1.0", "description": "Fast package manager"}}})
    assert it.name == "pnpm [npm -g]" and it.version == "9.1.0"


def test_editor_extensions(tmp_path):
    ext = tmp_path / "ms-python.python-2024.14.1"
    ext.mkdir()
    (ext / "package.json").write_text(json.dumps({"displayName": "Python", "description": "Python support",
                                                  "publisher": "ms-python"}))
    (tmp_path / "extensions.json").write_text(json.dumps([{
        "identifier": {"id": "ms-python.python"}, "version": "2024.14.1",
        "relativeLocation": ext.name, "metadata": {"installedTimestamp": 1758470400000}}]))
    (it,) = parse_extensions("Cursor", tmp_path)
    assert it.name == "Python [Cursor extension]" and it.description == "Python support"
    assert it.install_time.year == 2025


def test_scoop_and_choco(tmp_path):
    app = tmp_path / "apps" / "ripgrep"
    (app / "14.1.0").mkdir(parents=True)
    (app / "current").mkdir()
    (app / "current" / "manifest.json").write_text(json.dumps({"version": "14.1.0", "description": "Fast grep"}))
    (s,) = parse_scoop_apps(tmp_path / "apps", "user")
    assert s.version == "14.1.0" and s.description == "Fast grep"

    lib = tmp_path / "lib" / "git"
    lib.mkdir(parents=True)
    (lib / "git.nuspec").write_text(
        '<?xml version="1.0"?><package xmlns="http://schemas.microsoft.com/packaging/2015/06/nuspec.xsd">'
        "<metadata><id>git</id><version>2.46.0</version><title>Git</title><summary>Version control</summary>"
        "</metadata></package>")
    (c,) = parse_choco_lib(tmp_path / "lib")
    assert c.name == "Git [choco]" and c.version == "2.46.0" and c.description == "Version control"
