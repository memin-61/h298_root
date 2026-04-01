#!/usr/bin/env python3
import re
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cwmp import CWMPEngine

CWMP_ID_RX = re.compile(r"<(?:\w+:)?ID[^>]*>(.*?)</(?:\w+:)?ID>", re.I | re.S)
CWMP_NS_DEFAULT = "urn:dslforum-org:cwmp-1-0"


class CWMPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "uvicorn"
    sys_version = ""

    def do_POST(self) -> None:
        app = self.server.app  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8", errors="ignore")
        if self.path not in app.cwmp_paths and self.path != "/":
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        cwmp_id = _first(CWMP_ID_RX, body, "1")
        if app.cwmp.is_inform(body):
            record = app.cwmp.parse_inform(body, self.client_address[0])
            app.logger.log(f"[cwmp] Inform received serial={record.get('serial_number', 'unknown')} ip={self.client_address[0]}")
            saved_inform = app.archive.save(record.get("serial_number", "unknown"), "inform", body)
            app.logger.log(f"[archive] saved inform -> {saved_inform}")
            app.on_inform(record.get("serial_number", ""))
            xml = app.cwmp.build_inform_response(cwmp_id, record.get("cwmp_ns") or CWMP_NS_DEFAULT)
            saved_response = app.archive.save_bytes(record.get("serial_number", "unknown"), "acs_response", xml)
            app.logger.log(f"[archive] saved acs_response -> {saved_response}")
            self._send_xml(xml)
            return
        serial = app.cwmp.find_by_ip(self.client_address[0])
        if serial:
            record = app.cwmp.get_or_create_record(serial)
            kind = "empty" if app.cwmp.is_empty_post(body) else "rpc"
            saved_request = app.archive.save(record.get("serial_number", "unknown"), kind, body)
            app.logger.log(f"[archive] saved {kind} -> {saved_request}")
            response_kind = app.cwmp.rpc_response_kind(body)
            app.logger.log(f"[cwmp] POST kind={kind} serial={record.get('serial_number', 'unknown')} response_kind={response_kind or 'none'}")
            app.cwmp.parse_rpc_response(body, record)
            if kind == "rpc":
                app.on_rpc_response(record, response_kind)
                rpc = app.cwmp.get_next_rpc(record)
                app.logger.log(f"[cwmp] next_rpc={(rpc.get('name') if rpc else 'none')} serial={record.get('serial_number', 'unknown')}")
                xml = app.cwmp.rpc_to_xml(record, rpc, cwmp_id) if rpc else app.cwmp.build_empty_response(cwmp_id, record.get("cwmp_ns") or CWMP_NS_DEFAULT)
                saved_response = app.archive.save_bytes(record.get("serial_number", "unknown"), "acs_response", xml)
                app.logger.log(f"[archive] saved acs_response -> {saved_response}")
                self._send_xml(xml)
                return
            if app.cwmp.is_empty_post(body):
                rpc = app.cwmp.get_next_rpc(record)
                app.logger.log(f"[cwmp] empty POST next_rpc={(rpc.get('name') if rpc else 'none')} serial={record.get('serial_number', 'unknown')}")
                xml = app.cwmp.rpc_to_xml(record, rpc, cwmp_id) if rpc else app.cwmp.build_empty_response(cwmp_id, record.get("cwmp_ns") or CWMP_NS_DEFAULT)
                saved_response = app.archive.save_bytes(record.get("serial_number", "unknown"), "acs_response", xml)
                app.logger.log(f"[archive] saved acs_response -> {saved_response}")
                self._send_xml(xml)
                return
        self._send_xml(app.cwmp.build_empty_response(cwmp_id, CWMP_NS_DEFAULT))

    def _send_xml(self, payload: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()

    def log_message(self, format: str, *args: Any) -> None:
        return


class ACSServer:
    def __init__(self, app: Any):
        self.app = app
        self.servers: list[ThreadingHTTPServer] = []
        self.threads = []

    def start(self) -> None:
        for port in self.app.http_ports:
            httpd = ThreadingHTTPServer((self.app.http_host, port), CWMPHandler)
            httpd.app = self.app  # type: ignore[attr-defined]
            import threading

            thread = threading.Thread(target=httpd.serve_forever, daemon=True)
            thread.start()
            self.servers.append(httpd)
            self.threads.append(thread)

    def stop(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()


def _first(rx: re.Pattern[str], body: str, default: str = "") -> str:
    match = rx.search(body)
    return match.group(1).strip() if match else default
