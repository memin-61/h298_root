#!/usr/bin/env python3
import threading
import time

class ARPResponder(threading.Thread):
    def __init__(self, iface: str, server_ip: str):
        super().__init__(daemon=True)
        self.iface = iface
        self.server_ip = server_ip
        self.stop_event = threading.Event()
        self.expected_vlan_stack: list[int] = []

    def set_expected_vlan_stack(self, vlan_stack: list[int] | None) -> None:
        self.expected_vlan_stack = list(vlan_stack or [])

    def stop(self) -> None:
        self.stop_event.set()

    def run(self) -> None:
        try:
            from scapy.all import ARP, AsyncSniffer, Dot1Q, Ether, get_if_hwaddr, sendp  # type: ignore
        except Exception:
            return
        local_mac = get_if_hwaddr(self.iface)

        def handle(pkt):
            if not pkt.haslayer(ARP) or not pkt.haslayer(Ether) or pkt[ARP].op != 1:
                return
            if pkt[ARP].pdst != self.server_ip:
                return
            if pkt[Ether].src.lower() == local_mac.lower():
                return
            if pkt[ARP].psrc == self.server_ip:
                return
            if pkt[ARP].hwsrc.lower() == local_mac.lower():
                return
            reply = Ether(src=local_mac, dst=pkt[Ether].src)
            for vlan in self.expected_vlan_stack:
                reply /= Dot1Q(vlan=vlan)
            reply /= ARP(op=2, hwsrc=local_mac, psrc=self.server_ip, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc)
            sendp(reply, iface=self.iface, verbose=False)

        sniffer = AsyncSniffer(iface=self.iface, prn=handle, store=False)
        sniffer.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(0.5)
        finally:
            sniffer.stop()
