from zeroconf import ServiceBrowser, Zeroconf
from PyQt5.QtCore import QObject, pyqtSignal
import logging

class DeviceDiscovery(QObject):
    device_found = pyqtSignal(str, str)  # name, address
    device_removed = pyqtSignal(str)     # name

    def __init__(self, service_type="_ftp._tcp.local."):
        super().__init__()
        self.zeroconf = Zeroconf()
        self.service_type = service_type
        self.browser = ServiceBrowser(self.zeroconf, self.service_type, handlers=[self.on_service_state_change])
        logging.basicConfig(level=logging.DEBUG)

    def on_service_state_change(self, zeroconf, service_type, name, state_change):
        logging.debug(f"Service state change: {state_change.name} for {name}")
        if state_change.name == "Added":
            info = zeroconf.get_service_info(service_type, name)
            if info:
                # Fix address extraction: addresses is a list of bytes, convert to IPv4 string
                if info.addresses:
                    address_bytes = info.addresses[0]
                    address = ".".join(str(b) for b in address_bytes)
                else:
                    address = "Unknown"
                logging.debug(f"Device found: {name} at {address}")
                self.device_found.emit(name, address)
        elif state_change.name == "Removed":
            logging.debug(f"Device removed: {name}")
            self.device_removed.emit(name)

    def close(self):
        self.zeroconf.close()
