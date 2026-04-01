#!/usr/bin/env python3
import re
import subprocess
import sys
import time


def windows_run(cmd: list[str], timeout: float | None = None) -> tuple[int, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.returncode, (proc.stderr or proc.stdout).strip()


def windows_run_powershell(script: str) -> tuple[int, str]:
    return windows_run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])


def windows_npcap_status() -> tuple[bool, str]:
    if sys.platform != "win32":
        return True, ""

    for service_name in ("npcap", "npf"):
        code, out = windows_run(["sc", "query", service_name])
        text = (out or "").lower()
        if code == 0 and "service_name" in text:
            if "running" in text:
                return True, f"Npcap service '{service_name}' is running"
            return True, f"Npcap service '{service_name}' is installed"

    return False, "Npcap was not detected. Install Npcap (WinPcap compatible mode) and restart this tool."


def windows_list_adapters() -> list[dict[str, str]]:
    code, out = windows_run_powershell(
        "Get-NetAdapter | Select-Object -Property Name, Status, MacAddress, InterfaceDescription | ConvertTo-Json"
    )
    if code != 0:
        return []
    try:
        import json

        data = json.loads(out)
        if isinstance(data, dict):
            data = [data]
        result: list[dict[str, str]] = []
        for item in data:
            name = str(item.get("Name") or "").strip()
            if not name:
                continue
            result.append(
                {
                    "name": name,
                    "status": str(item.get("Status") or "Unknown").strip() or "Unknown",
                    "mac": str(item.get("MacAddress") or "").replace("-", ":").lower(),
                    "description": str(item.get("InterfaceDescription") or "").strip(),
                }
            )
        return sorted(result, key=lambda row: (row.get("status", "").lower() != "up", row.get("name", "")))
    except Exception:
        return []


def windows_get_interface_mac(interface: str) -> str | None:
    code, out = windows_run_powershell(
        "(Get-NetAdapter -Name '{iface}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty MacAddress)"
        .format(iface=interface.replace("'", "''"))
    )
    if code != 0:
        return None
    raw = (out or "").strip()
    if not raw:
        return None
    mac = raw.replace("-", ":").lower()
    return mac if re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}", mac) else None


def windows_clear_arp_cache() -> None:
    for cmd in (["netsh", "interface", "ip", "delete", "arpcache"], ["arp", "-d", "*"]):
        code, _ = windows_run(cmd)
        if code == 0:
            return


def windows_prepare_self_dhcp(interface: str) -> None:
    escaped = interface.replace("'", "''")
    windows_run_powershell(
        "$ErrorActionPreference = 'Stop'; "
        f"$if = '{escaped}'; "
        "Get-NetAdapter -Name $if | Out-Null; "
        "Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "
        "Set-NetIPInterface -InterfaceAlias $if -AddressFamily IPv4 -Dhcp Enabled | Out-Null; "
        "Set-DnsClientServerAddress -InterfaceAlias $if -ResetServerAddresses -ErrorAction SilentlyContinue | Out-Null"
    )
    windows_run_powershell(
        "$ErrorActionPreference = 'SilentlyContinue'; "
        f"Restart-NetAdapter -Name '{escaped}' -Confirm:$false; "
        "Start-Sleep -Milliseconds 800"
    )


def windows_self_assign_ipv4(interface: str, ip: str, should_stop=None, max_wait_seconds: float = 120.0) -> None:
    escaped = interface.replace("'", "''")

    def request_lease() -> None:
        windows_run_powershell(
            f"$ErrorActionPreference = 'SilentlyContinue'; Release-DhcpLease -InterfaceAlias '{escaped}'; Start-Sleep -Milliseconds 200; Request-DhcpLease -InterfaceAlias '{escaped}'"
        )
        windows_run(["ipconfig", "/renew", interface])

    request_lease()
    deadline = time.time() + max_wait_seconds
    last_retry = 0.0
    last_status_up = False
    while time.time() < deadline:
        if should_stop is not None and should_stop():
            raise RuntimeError("startup canceled")
        code, out = windows_run_powershell(
            (
                "$if = '{iface}'; "
                "$status = (Get-NetAdapter -Name $if -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Status); "
                "$ips = Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty IPAddress; "
                "if ($status) {{ Write-Output ('STATUS=' + $status) }}; "
                "if ($ips) {{ Write-Output ('IPS=' + ($ips -join ',')) }}"
            ).format(iface=escaped)
        )
        text = out or ""
        if code == 0 and re.search(rf"\b{re.escape(ip)}\b", text):
            return
        status_match = re.search(r"STATUS=([^\r\n]+)", text)
        status = status_match.group(1).strip() if status_match else "Unknown"
        is_up = status.lower() == "up"
        if not is_up:
            last_status_up = False
            time.sleep(1.0)
            continue
        now = time.time()
        if (not last_status_up) or (now - last_retry >= 3.0):
            request_lease()
            last_retry = now
        last_status_up = True
        time.sleep(1.0)
    raise RuntimeError(f"adapter {interface} did not acquire {ip} within timeout")


def windows_pin_static_ipv4(interface: str, ip: str) -> None:
    escaped = interface.replace("'", "''")
    code, msg = windows_run_powershell(
        "$ErrorActionPreference = 'Stop'; "
        f"$if = '{escaped}'; "
        "Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "
        f"New-NetIPAddress -InterfaceAlias $if -IPAddress '{ip}' -PrefixLength 24 -Type Unicast | Out-Null; "
        "Set-NetIPInterface -InterfaceAlias $if -AddressFamily IPv4 -Dhcp Disabled | Out-Null"
    )
    if code != 0:
        raise RuntimeError(msg or f"failed to pin static IPv4 {ip}")


def windows_set_dhcp(interface: str) -> None:
    escaped = interface.replace("'", "''")
    windows_run_powershell(
        "$ErrorActionPreference = 'Stop'; "
        f"$if = '{escaped}'; "
        "Get-NetRoute -InterfaceAlias $if -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.NextHop -eq '0.0.0.0' } | "
        "Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue; "
        "Get-NetIPAddress -InterfaceAlias $if -AddressFamily IPv4 -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue; "
        "Set-NetIPInterface -InterfaceAlias $if -AddressFamily IPv4 -Dhcp Enabled | Out-Null; "
        "Set-DnsClientServerAddress -InterfaceAlias $if -ResetServerAddresses -ErrorAction SilentlyContinue | Out-Null; "
        "Release-DhcpLease -InterfaceAlias $if -ErrorAction SilentlyContinue | Out-Null; "
        "Start-Sleep -Milliseconds 250; "
        "Request-DhcpLease -InterfaceAlias $if -ErrorAction SilentlyContinue | Out-Null"
    )
    windows_run(["ipconfig", "/renew", interface])


def windows_add_neighbor(interface: str, address: str, mac: str) -> None:
    windows_run(["netsh", "interface", "ipv4", "add", "neighbors", f"name={interface}", f"address={address}", f"neighbor={mac}", "store=active"])


def windows_delete_neighbor(interface: str, address: str) -> None:
    windows_run(["netsh", "interface", "ipv4", "delete", "neighbors", f"name={interface}", f"address={address}"])


def windows_add_firewall_rule(name: str, ports: list[int]) -> None:
    ports_csv = ",".join(str(port) for port in sorted(set(ports)))
    windows_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    windows_run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=allow", "protocol=TCP", f"localport={ports_csv}", "profile=any"])


def windows_delete_firewall_rule(name: str) -> None:
    windows_run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])


def require_windows() -> None:
    if sys.platform != "win32":
        raise SystemExit("H298A V1.0 root enabler currently supports Windows only")
