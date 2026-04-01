#!/usr/bin/env python3
import time
from dataclasses import dataclass
from pathlib import Path

from .acs_server import ACSServer
from .arp_service import ARPResponder
from .common import FileLogger
from .cwmp import CWMPEngine
from .dhcp_service import DHCPService
from .storage import RequestArchive
from .network_utils import (
    require_windows,
    windows_add_firewall_rule,
    windows_add_neighbor,
    windows_clear_arp_cache,
    windows_delete_firewall_rule,
    windows_delete_neighbor,
    windows_get_interface_mac,
    windows_pin_static_ipv4,
    windows_prepare_self_dhcp,
    windows_self_assign_ipv4,
    windows_set_dhcp,
)


@dataclass
class AppConfig:
    host: str
    iface: str
    http_ports: list[int]
    root: Path
    enable_dhcp: bool = True
    set_ip: bool = True
    restore_dhcp: bool = True
    dns_answer_ip: str = "10.116.13.100"
    pppoe_server_ip: str = "10.116.13.100"
    pppoe_client_ip: str = "10.116.13.101"
    local_mac: str | None = None
    router_mac: str | None = None
    enable_root: bool = False
    root_password: str = "Passwd123"


def validate_root_password(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    if not any(ch.isdigit() for ch in password):
        return False, "Password must include at least one number"
    lower = password.lower()
    if lower != "passwd123":
        for forbidden in ("pass", "password", "root", "admin"):
            if forbidden in lower:
                return False, f"Password cannot contain '{forbidden}'"
    return True, ""


class H298ARootEnablerApp:
    ROOT_QUERY_NAMES = [
        "InternetGatewayDevice.X_TT.Configuration.Shell.Enable",
        "InternetGatewayDevice.X_TT.Configuration.Shell.Password",
        "InternetGatewayDevice.X_TT.Users.User.2.Enable",
        "InternetGatewayDevice.X_TT.Users.User.2.Username",
        "InternetGatewayDevice.X_TT.Users.User.2.Password",
        "InternetGatewayDevice.X_TT.Users.User.2.RemoteAccessCapable",
        "InternetGatewayDevice.X_TT.Users.User.2.LocalAccessCapable",
        "InternetGatewayDevice.X_TT.UserInterface.RemoteAccess.Enable",
        "InternetGatewayDevice.X_ZTE-COM_SSH.UserName",
        "InternetGatewayDevice.X_ZTE-COM_SSH.Password",
        "InternetGatewayDevice.X_ZTE-COM_SSH.Port",
    ]
    def _root_set_values(self) -> list[tuple[str, str, str]]:
        password = self.config.root_password
        return [
            ("InternetGatewayDevice.X_TT.Configuration.Shell.Enable", "1", "boolean"),
            ("InternetGatewayDevice.X_TT.Configuration.Shell.Password", password, "string"),
            ("InternetGatewayDevice.X_TT.Users.User.2.Enable", "1", "boolean"),
            ("InternetGatewayDevice.X_TT.Users.User.2.Username", "root", "string"),
            ("InternetGatewayDevice.X_TT.Users.User.2.Password", password, "string"),
            ("InternetGatewayDevice.X_TT.Users.User.2.RemoteAccessCapable", "1", "boolean"),
            ("InternetGatewayDevice.X_TT.Users.User.2.LocalAccessCapable", "1", "boolean"),
            ("InternetGatewayDevice.X_TT.UserInterface.RemoteAccess.Enable", "1", "boolean"),
            ("InternetGatewayDevice.X_ZTE-COM_SSH.UserName", "root", "string"),
            ("InternetGatewayDevice.X_ZTE-COM_SSH.Password", password, "string"),
            ("InternetGatewayDevice.X_ZTE-COM_SSH.Port", "22", "unsignedInt"),
        ]

    def __init__(self, config: AppConfig):
        self.config = config
        self.cwmp = CWMPEngine()
        self.logger = FileLogger(config.root / "console.log")
        self.archive = RequestArchive(config.root)
        self.http_host = config.host
        self.http_ports = config.http_ports
        self.cwmp_paths = {"/", "/cwmpWeb/WGCCPEMgt", "/cwmpWeb/WGCPEMgt"}
        self.acs_server = ACSServer(self)
        self.dhcp_service: DHCPService | None = None
        self.arp_service: ARPResponder | None = None
        self.firewall_rule = f"H298A V1.0 Root Enabler {config.iface}"
        self.root_state: dict[str, str] = {}
        self.root_serial: str | None = None
        self.stop_requested = False
        self.exit_requested = False

    def _discover_mac_addresses(self) -> None:
        if not self.config.local_mac:
            local_mac = windows_get_interface_mac(self.config.iface)
            if local_mac:
                self.config.local_mac = local_mac

    def on_modem_dhcp_ack(self, modem_mac: str, vlan_stack: list[int] | None = None) -> None:
        if not self.config.router_mac:
            self.config.router_mac = modem_mac
            windows_add_neighbor(self.config.iface, self.config.pppoe_client_ip, modem_mac)
        if self.arp_service is not None:
            self.arp_service.set_expected_vlan_stack(vlan_stack)
        self._emit_arp_presence_burst(modem_mac, vlan_stack)

    def _emit_arp_presence_burst(self, modem_mac: str, vlan_stack: list[int] | None = None) -> None:
        try:
            import scapy.all as scapy  # type: ignore
        except Exception:
            return
        try:
            local_mac = scapy.get_if_hwaddr(self.config.iface)
        except Exception:
            return
        dst = modem_mac or "ff:ff:ff:ff:ff:ff"
        pkt = scapy.Ether(src=local_mac, dst=dst)
        for vlan in list(vlan_stack or []):
            pkt /= scapy.Dot1Q(vlan=vlan)
        pkt /= scapy.ARP(
            op=2,
            hwsrc=local_mac,
            psrc=self.config.pppoe_server_ip,
            hwdst=dst,
            pdst=self.config.pppoe_client_ip,
        )
        for _ in range(3):
            scapy.sendp(pkt, iface=self.config.iface, verbose=False)
            time.sleep(0.12)

    def on_inform(self, serial: str) -> None:
        if not self.config.enable_root:
            return
        if self.root_serial is None:
            self.root_serial = serial
        if serial != self.root_serial:
            return
        if self.root_state.get(serial) in {"precheck", "set", "done", "failed"}:
            return
        self.root_state[serial] = "precheck"
        self.cwmp.queue_rpc(serial, "GetParameterValues", {"names": list(self.ROOT_QUERY_NAMES)})

    def on_rpc_response(self, record: dict, response_kind: str | None) -> None:
        serial = record.get("serial_number", "")
        state = self.root_state.get(serial)
        if not self.config.enable_root or serial != self.root_serial:
            return
        if state == "precheck" and response_kind == "GetParameterValuesResponse":
            params = record.get("parameters", {})
            missing = [name for name in self.ROOT_QUERY_NAMES if name not in params]
            if missing:
                self.root_state[serial] = "failed"
                return
            self.root_state[serial] = "set"
            self.cwmp.queue_rpc(serial, "SetParameterValues", {"values": self._root_set_values()})
            return
        if state == "set" and response_kind == "SetParameterValuesResponse":
            self.root_state[serial] = "done"
            if not self.exit_requested:
                self.exit_requested = True

    def start(self) -> None:
        self.stop_requested = False
        self.exit_requested = False
        if self.config.set_ip:
            require_windows()
            windows_clear_arp_cache()
            windows_prepare_self_dhcp(self.config.iface)
        self._discover_mac_addresses()
        windows_add_firewall_rule(self.firewall_rule, self.http_ports)
        if self.config.router_mac:
            windows_add_neighbor(self.config.iface, self.config.pppoe_client_ip, self.config.router_mac)
        self.acs_server.start()
        if self.config.enable_dhcp:
            self.dhcp_service = DHCPService(self.config.iface, self.config.pppoe_server_ip, self.config.pppoe_client_ip, self.config.local_mac, on_modem_ack=self.on_modem_dhcp_ack)
            if self.config.set_ip:
                self.dhcp_service.set_modem_serving_enabled(False)
            self.dhcp_service.start()
        time.sleep(0.5)
        self.arp_service = ARPResponder(self.config.iface, self.config.pppoe_server_ip)
        self.arp_service.start()
        if self.config.set_ip:
            windows_self_assign_ipv4(self.config.iface, self.config.dns_answer_ip, should_stop=lambda: self.stop_requested)
            time.sleep(0.5)
            if self.stop_requested:
                raise RuntimeError("startup canceled")
            windows_pin_static_ipv4(self.config.iface, self.config.dns_answer_ip)
            if self.dhcp_service is not None:
                self.dhcp_service.lock_local_lease()
                self.dhcp_service.set_modem_serving_enabled(True)

    def stop(self) -> None:
        self.stop_requested = True
        if self.arp_service is not None:
            self.arp_service.stop()
        if self.dhcp_service is not None:
            self.dhcp_service.stop()
        self.acs_server.stop()
        if self.config.router_mac:
            windows_delete_neighbor(self.config.iface, self.config.pppoe_client_ip)
        windows_delete_firewall_rule(self.firewall_rule)
        if self.config.set_ip and self.config.restore_dhcp:
            windows_set_dhcp(self.config.iface)
