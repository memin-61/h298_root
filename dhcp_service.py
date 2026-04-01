#!/usr/bin/env python3
import threading
import time

class DHCPService(threading.Thread):
    def __init__(self, iface: str, server_ip: str, client_ip: str, local_mac: str | None, on_modem_ack=None):
        super().__init__(daemon=True)
        self.iface = iface
        self.server_ip = server_ip
        self.client_ip = client_ip
        self.local_mac = (local_mac or "").lower()
        self.lease_time = 86400
        self.stop_event = threading.Event()
        self.local_lease_locked = False
        self.on_modem_ack = on_modem_ack
        self.acs_url = f"http://{self.server_ip}:8015/"
        self.modem_serving_enabled = True

    def lock_local_lease(self) -> None:
        if self.local_mac and not self.local_lease_locked:
            self.local_lease_locked = True

    def set_modem_serving_enabled(self, enabled: bool) -> None:
        self.modem_serving_enabled = enabled

    def stop(self) -> None:
        self.stop_event.set()

    def lease_for_mac(self, mac: str) -> str | None:
        mac = mac.lower()
        if self.local_mac and mac == self.local_mac:
            return None if self.local_lease_locked else self.server_ip
        return self.client_ip

    def run(self) -> None:
        try:
            from scapy.all import AsyncSniffer, BOOTP, DHCP, Dot1Q, Ether, IP, UDP, sendp  # type: ignore
        except Exception:
            return

        try:
            from scapy.all import get_if_hwaddr  # type: ignore

            local_mac = get_if_hwaddr(self.iface)
        except Exception:
            local_mac = None

        def copy_l2(pkt, dst: str):
            src_mac = local_mac or pkt[Ether].dst
            base = Ether(dst=dst, src=src_mac)
            current = base
            layer = pkt.payload
            while layer is not None and layer.__class__.__name__ == "Dot1Q":
                current /= Dot1Q(vlan=getattr(layer, "vlan", 0), prio=getattr(layer, "prio", 0), type=getattr(layer, "type", 0x0800))
                current = current.payload
                layer = layer.payload
            return base

        def vlan_stack_from(pkt) -> list[int]:
            stack: list[int] = []
            layer = pkt.payload
            while layer is not None and layer.__class__.__name__ == "Dot1Q":
                stack.append(int(getattr(layer, "vlan", 0)))
                layer = layer.payload
            return stack

        def handle(pkt):
            if not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
                return
            msg_type = None
            for opt in pkt[DHCP].options:
                if isinstance(opt, tuple) and opt[0] == "message-type":
                    msg_type = opt[1]
                    break
            if msg_type not in (1, 3, "discover", "request"):
                return
            xid = int(pkt[BOOTP].xid)
            yiaddr = self.lease_for_mac(pkt[Ether].src)
            if yiaddr is None:
                return
            mac_lower = pkt[Ether].src.lower()
            is_local = bool(self.local_mac and mac_lower == self.local_mac)
            if yiaddr == self.client_ip and not is_local and not self.modem_serving_enabled:
                return
            if yiaddr == self.server_ip and (not self.local_mac or pkt[Ether].src.lower() != self.local_mac):
                return
            reply_type = "offer" if msg_type in (1, "discover") else "ack"
            options = [
                ("message-type", reply_type),
                ("server_id", self.server_ip),
                ("router", self.server_ip),
                ("name_server", self.server_ip),
                ("subnet_mask", "255.255.255.0"),
                ("broadcast_address", "10.116.13.255"),
                ("lease_time", self.lease_time),
            ]
            if yiaddr == self.client_ip:
                vendor_blob = bytes([0x01, len(self.acs_url)]) + self.acs_url.encode("ascii")
                options.append((43, vendor_blob))
            options.append("end")
            resp = copy_l2(pkt, pkt[Ether].src) / IP(src=self.server_ip, dst="255.255.255.255") / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=yiaddr, siaddr=self.server_ip, xid=pkt[BOOTP].xid, chaddr=pkt[BOOTP].chaddr) / DHCP(options=options)
            sendp(resp, iface=self.iface, verbose=False)
            vstack = vlan_stack_from(pkt)
            if reply_type == "ack" and yiaddr == self.client_ip:
                if self.on_modem_ack is not None:
                    try:
                        self.on_modem_ack(pkt[Ether].src.lower(), vstack)
                    except Exception:
                        pass

        sniffer = AsyncSniffer(iface=self.iface, prn=handle, store=False, filter="udp and (port 67 or port 68)")
        sniffer.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        finally:
            sniffer.stop()
