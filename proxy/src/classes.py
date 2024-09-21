from watchdog.events import RegexMatchingEventHandler
from src.pcap_export import PCAPExporter
from src.filter_modules import import_modules
from dataclasses import dataclass
from typing import Dict, List
import uuid
from dotenv import load_dotenv
import os
load_dotenv()

PCAP_ExporterON = os.getenv("PCAP_Export_Enabled", "False").lower() == "true"

class ModuleWatchdog(RegexMatchingEventHandler):
    def __init__(self, regexes, in_module, out_module, name):
        self.in_module = in_module
        self.out_module = out_module
        self.name = name
        super().__init__(regexes=regexes)

    def on_modified(self, event):
        print(self.name, "RELOADING", {event.src_path})
        try:
            self.in_module, self.out_module = import_modules(self.name)
        except Exception as e:
            print(self.name, "ERROR in reloading:", str(e))


@dataclass
class SSLConfig:
    server_certificate: str
    server_key: str
    client_certificate: str = None
    client_key: str = None
    ca_file: str = None


class Service:
    def __init__(self, name: str, target_ip: str, target_port: int, listen_port: int, listen_ip: str = "::", http = False, ssl=None):
        self.name = name
        self.target_ip = target_ip
        self.target_port = target_port
        self.listen_port = listen_port
        self.listen_ip = listen_ip
        self.http = http
        if ssl:
            self.ssl = SSLConfig(**ssl)
        else:
            self.ssl = None
        self.exporters:Dict[str, PCAPExporter] = {}
    def _generate_session_id(self) -> str:
        return str(uuid.uuid4())

    def add_exporter(self):
        if not PCAP_ExporterON:
            return None, None
        session_id = self._generate_session_id()
        pcap_exporter = PCAPExporter(self.name)
        if session_id in self.exporters:
            print(f"Exporter for session {session_id} already exists.")
        else:
            self.exporters[session_id] = pcap_exporter
            print(f"Added exporter for Session {session_id}")

        return session_id, pcap_exporter
    
    def export_remove_exporter(self, session_id: str):
        if not PCAP_ExporterON:
            return
        if session_id not in self.exporters:
            print(f"Exporter for session {session_id} not found.")
        else:
            self.exporters[session_id].export()
            del self.exporters[session_id]
            print(f"Removed exporter for Session {session_id}")

    def export_all(self):
        if not PCAP_ExporterON:
            return 
        for session_id, exporter in self.exporters.items():
            try:
                exporter.export()
                self.remove_exporter(session_id)
                print(f"Exported Data from Session {session_id}")
            except Exception as e:
                print(f"Error while exporting session {session_id}: {str(e)}")



@dataclass
class Config:
    services: List[Service]
    global_config: dict
