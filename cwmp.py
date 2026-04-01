#!/usr/bin/env python3
import re
import time

CWMP_NS_DEFAULT = "urn:dslforum-org:cwmp-1-0"


class CWMPEngine:
    SERIAL_RX = re.compile(r"<(?:\w+:)?SerialNumber[^>]*>(.*?)</(?:\w+:)?SerialNumber>", re.I | re.S)
    ID_RX = re.compile(r"<(?:\w+:)?ID[^>]*>(.*?)</(?:\w+:)?ID>", re.I | re.S)
    PARAM_RX = re.compile(r"<(?:\w+:)?ParameterValueStruct[^>]*>.*?<Name[^>]*>(.*?)</Name>.*?<Value[^>]*>(.*?)</Value>.*?</(?:\w+:)?ParameterValueStruct>", re.I | re.S)
    EMPTY_POST_RX = re.compile(r"^\s*(?:<\?xml.*?\?>)?\s*(?:<[^>]+Envelope[^>]*>\s*)?(?:<[^>]+Header[^>]*>.*?</[^>]+Header>\s*)?(?:<[^>]+Body[^>]*>\s*</[^>]+Body>|</[^>]+Envelope>)?\s*$", re.I | re.S)

    def __init__(self, inform_interval: int | None = 30):
        self.inform_interval = inform_interval
        self.records: dict[str, dict] = {}
        self.ip_to_serial: dict[str, str] = {}

    def _record(self, serial: str) -> dict:
        rec = self.records.get(serial)
        if rec is None:
            rec = {
                "serial_number": serial,
                "cwmp_ns": CWMP_NS_DEFAULT,
                "ip_address": "",
                "inform_count": 0,
                "parameters": {},
                "rpc_queue": [],
            }
            self.records[serial] = rec
        return rec

    def get_or_create_record(self, serial: str) -> dict:
        return self._record(serial)

    def detect_ns(self, body: str) -> str:
        match = re.search(r'xmlns:(\w+)="(urn:dslforum-org:cwmp-[^"]+)"', body)
        return match.group(2) if match else CWMP_NS_DEFAULT

    def is_inform(self, body: str) -> bool:
        return bool(re.search(r"<[^>]*:Inform[\s>]", body) or re.search(r"<Inform[\s>]", body))

    def is_empty_post(self, body: str) -> bool:
        return self.EMPTY_POST_RX.match(body or "") is not None

    def rpc_response_kind(self, body: str) -> str | None:
        for name in ("GetParameterValuesResponse", "SetParameterValuesResponse"):
            if name in body:
                return name
        return None

    def parse_inform(self, body: str, client_ip: str) -> dict:
        serial = self._first(self.SERIAL_RX, body, "unknown")
        rec = self._record(serial)
        rec["cwmp_ns"] = self.detect_ns(body)
        rec["ip_address"] = client_ip
        rec["inform_count"] = int(rec.get("inform_count", 0)) + 1
        for name, value in self.PARAM_RX.findall(body):
            rec["parameters"][name.strip()] = value.strip()
        self.ip_to_serial[client_ip] = serial
        return rec

    def find_by_ip(self, ip: str) -> str | None:
        return self.ip_to_serial.get(ip)

    def parse_rpc_response(self, body: str, rec: dict) -> None:
        pairs = self.PARAM_RX.findall(body)
        if pairs:
            for name, value in pairs:
                rec["parameters"][name.strip()] = value.strip()

    def queue_rpc(self, serial: str, name: str, payload: dict) -> None:
        rec = self._record(serial)
        rec["rpc_queue"].append({"name": name, "payload": payload})

    def get_next_rpc(self, rec: dict) -> dict | None:
        queue = rec.get("rpc_queue", [])
        if queue:
            return queue.pop(0)
        return None

    def build_inform_response(self, cwmp_id: str, ns: str) -> bytes:
        return (
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            f"<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:cwmp=\"{ns}\">"
            f"<SOAP-ENV:Header><cwmp:ID SOAP-ENV:mustUnderstand=\"1\">{self._xml(cwmp_id)}</cwmp:ID></SOAP-ENV:Header>"
            "<SOAP-ENV:Body><cwmp:InformResponse><MaxEnvelopes>1</MaxEnvelopes></cwmp:InformResponse></SOAP-ENV:Body></SOAP-ENV:Envelope>"
        ).encode("utf-8")

    def build_empty_response(self, cwmp_id: str, ns: str) -> bytes:
        return b""

    def build_get_parameter_names(self, cwmp_id: str, ns: str, path: str, next_level: int) -> bytes:
        return self._soap(cwmp_id, ns, f"<cwmp:GetParameterNames><ParameterPath xsi:type=\"xsd:string\">{self._xml(path)}</ParameterPath><NextLevel xsi:type=\"xsd:boolean\">{int(next_level)}</NextLevel></cwmp:GetParameterNames>")

    def build_get_parameter_values(self, cwmp_id: str, ns: str, names: list[str]) -> bytes:
        items = "".join(f"<string>{self._xml(name)}</string>" for name in names)
        return self._soap(cwmp_id, ns, f"<cwmp:GetParameterValues><ParameterNames SOAP-ENV:arrayType=\"xsd:string[{len(names)}]\">{items}</ParameterNames></cwmp:GetParameterValues>")

    def build_set_parameter_values(self, cwmp_id: str, ns: str, values: list[tuple[str, str, str]]) -> bytes:
        structs = []
        for name, value, xsd_type in values:
            structs.append(f"<ParameterValueStruct><Name>{self._xml(name)}</Name><Value xsi:type=\"xsd:{self._xml(xsd_type)}\">{self._xml(value)}</Value></ParameterValueStruct>")
        return self._soap(cwmp_id, ns, f"<cwmp:SetParameterValues><ParameterList SOAP-ENV:arrayType=\"cwmp:ParameterValueStruct[{len(values)}]\">{''.join(structs)}</ParameterList><ParameterKey>{int(time.time())}</ParameterKey></cwmp:SetParameterValues>")

    def rpc_to_xml(self, rec: dict, rpc: dict, cwmp_id: str) -> bytes:
        ns = rec.get("cwmp_ns") or CWMP_NS_DEFAULT
        name = rpc.get("name")
        payload = rpc.get("payload", {})
        if name == "GetParameterNames":
            return self.build_get_parameter_names(cwmp_id, ns, payload.get("path", "InternetGatewayDevice."), int(payload.get("next_level", 0)))
        if name == "GetParameterValues":
            return self.build_get_parameter_values(cwmp_id, ns, list(payload.get("names", [])))
        if name == "SetParameterValues":
            return self.build_set_parameter_values(cwmp_id, ns, list(payload.get("values", [])))
        return self.build_empty_response(cwmp_id, ns)

    def _soap(self, cwmp_id: str, ns: str, body: str) -> bytes:
        return (
            f"<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:cwmp=\"{ns}\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
            f"<SOAP-ENV:Header><cwmp:ID SOAP-ENV:mustUnderstand=\"1\">{self._xml(cwmp_id)}</cwmp:ID><cwmp:NoMoreRequest>0</cwmp:NoMoreRequest></SOAP-ENV:Header>"
            f"<SOAP-ENV:Body>{body}</SOAP-ENV:Body></SOAP-ENV:Envelope>"
        ).encode("utf-8")

    @staticmethod
    def _first(rx: re.Pattern[str], body: str, default: str = "") -> str:
        match = rx.search(body)
        return match.group(1).strip() if match else default

    @staticmethod
    def _xml(value: str) -> str:
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
