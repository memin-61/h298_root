#!/usr/bin/env python3
import argparse
import sys
import time
from pathlib import Path

try:
    from .app import AppConfig, H298ARootEnablerApp, validate_root_password
    from .network_utils import windows_list_adapters, windows_npcap_status
except ImportError:
    from minimal_h298a.app import AppConfig, H298ARootEnablerApp, validate_root_password
    from minimal_h298a.network_utils import windows_list_adapters, windows_npcap_status


def _is_windows_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _iface_is_usable_with_scapy(iface: str) -> bool:
    try:
        from scapy.all import get_if_hwaddr  # type: ignore

        get_if_hwaddr(iface)
        return True
    except Exception:
        return False


def _prompt_interface_selection() -> str | None:
    adapters = windows_list_adapters()
    if not adapters:
        return None

    print("[select] Choose network adapter:")
    for idx, item in enumerate(adapters, start=1):
        name = item.get("name", "")
        status = item.get("status", "")
        mac = item.get("mac", "")
        desc = item.get("description", "")
        usable = "ok" if _iface_is_usable_with_scapy(name) else "not-usable"
        print(f"  {idx}. {name} | {status} | {mac} | {usable}")
        if desc:
            print(f"     {desc}")

    while True:
        raw = input("Enter adapter number (or q to quit): ").strip().lower()
        if raw in {"q", "quit", "exit"}:
            return None
        if not raw.isdigit():
            print("[error] Please enter a valid number.")
            continue
        idx = int(raw)
        if idx < 1 or idx > len(adapters):
            print("[error] Number out of range.")
            continue
        chosen = adapters[idx - 1].get("name", "")
        if not _iface_is_usable_with_scapy(chosen):
            print(f"[error] Interface '{chosen}' is not usable by scapy. Choose another.")
            continue
        return chosen


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="H298A V1.0 Root Enabler (CLI)")
    parser.add_argument("-p", "--password", default="Passwd123", help="Root password to set")
    return parser


def main() -> int:
    args = _build_parser().parse_args()

    if not _is_windows_admin():
        print("[error] Run this tool as Administrator.")
        return 1

    ok_npcap, npcap_msg = windows_npcap_status()
    if not ok_npcap:
        print(f"[error] {npcap_msg}")
        return 1

    valid_pw, reason = validate_root_password(args.password)
    if not valid_pw:
        print(f"[error] Invalid password: {reason}")
        return 1

    iface = _prompt_interface_selection()
    if not iface:
        print("[info] No adapter selected.")
        return 1

    cfg = AppConfig(
        host="0.0.0.0",
        iface=iface,
        http_ports=[80, 8015],
        root=Path("C:/temp/h298"),
        set_ip=True,
        restore_dhcp=True,
        enable_root=True,
        root_password=args.password,
    )
    app = H298ARootEnablerApp(cfg)

    print("[info] H298A V1.0 Root Enabler (CLI)")
    print(f"[info] Adapter: {iface}")

    try:
        app.start()
        print("[info] Services started. Waiting for router CWMP session...")
        while True:
            if app.exit_requested:
                print("[ok] Device successfully rooted")
                print("[ok] Username: root")
                print(f"[ok] Password: {args.password}")
                print("[ok] Enable SSH under Easy Menu -> Local Access -> SSH Port")
                return 0
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("[info] Interrupted by user.")
        return 130
    except Exception as exc:
        print(f"[error] {exc}")
        return 1
    finally:
        try:
            app.stop()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
