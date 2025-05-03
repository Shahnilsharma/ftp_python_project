import sys
import os
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QPushButton,
    QFileDialog, QLabel, QListWidget, QHBoxLayout, QStatusBar, QLineEdit, QFormLayout
)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt
import threading
import ftp_core
from device_discovery import DeviceDiscovery
from permission_dialog import PermissionDialog
from ftp_core import PermissionFTPHandler
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.servers import FTPServer

class FTPServerThread(QThread):
    server_started = pyqtSignal()
    server_stopped = pyqtSignal()

    def __init__(self, directory, username="user", password="12345", parent=None):
        super().__init__(parent)
        self.directory = directory
        self.username = username
        self.password = password
        self._server = None
        self._running = False

    def run(self):
        authorizer = DummyAuthorizer()
        authorizer.add_user(self.username, self.password, self.directory, perm="elradfmw")

        handler = PermissionFTPHandler
        handler.authorizer = authorizer
        handler.passive_ports = range(60000, 65535)

        address = ("0.0.0.0", 2121)
        self._server = FTPServer(address, handler)
        self._running = True
        self.server_started.emit()
        try:
            self._server.serve_forever()
        except Exception as e:
            print(f"FTP Server error: {e}")
        self._running = False
        self.server_stopped.emit()

    def stop(self):
        if self._server:
            self._server.close_all()
            self._running = False

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secured Wireless FTP Server")
        self.resize(600, 400)

        self.directory = os.getcwd()
        self.ftp_thread = None

        # Known devices dictionary: {ip: {"name": str, "enabled": bool}}
        self.known_devices = {}

        # Device discovery
        self.device_discovery = DeviceDiscovery()
        self.device_discovery.device_found.connect(self.on_device_found)
        self.device_discovery.device_removed.connect(self.on_device_removed)

        # Timer to check permission queue
        self.permission_timer = QTimer()
        self.permission_timer.timeout.connect(self.check_permission_queue)
        self.permission_timer.start(500)  # check every 500 ms

        # Timer to check client event queue
        self.client_timer = QTimer()
        self.client_timer.timeout.connect(self.check_client_event_queue)
        self.client_timer.start(500)  # check every 500 ms

        self.init_ui()

    def init_ui(self):
        from PyQt5.QtWidgets import QListWidgetItem, QAbstractItemView, QGroupBox, QGridLayout, QCheckBox

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout()

        # Directory label and browse button
        dir_layout = QHBoxLayout()
        self.dir_label = QLabel(f"Shared Directory: {self.directory}")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_directory)
        dir_layout.addWidget(self.dir_label)
        dir_layout.addWidget(browse_btn)
        layout.addLayout(dir_layout)

        # User credentials input
        form_layout = QFormLayout()
        self.username_input = QLineEdit()
        self.username_input.setText("user")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setText("12345")
        form_layout.addRow("Username:", self.username_input)
        form_layout.addRow("Password:", self.password_input)
        layout.addLayout(form_layout)

        # FTP server address display
        self.address_label = QLabel("FTP Server Address: Not running")
        layout.addWidget(self.address_label)

        # Start and Stop buttons
        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start FTP Server")
        self.start_btn.clicked.connect(self.start_server)
        self.stop_btn = QPushButton("Stop FTP Server")
        self.stop_btn.clicked.connect(self.stop_server)
        self.stop_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)

        # Client monitoring list
        self.client_list = QListWidget()
        self.client_list.addItem("No clients connected")
        layout.addWidget(QLabel("Connected Clients:"))
        layout.addWidget(self.client_list)

        # Permanent client device list with multi-selection
        self.permanent_client_list = QListWidget()
        self.permanent_client_list.setSelectionMode(QAbstractItemView.MultiSelection)
        layout.addWidget(QLabel("Permanent Client Devices:"))
        layout.addWidget(self.permanent_client_list)

        # Button to browse and select folder to share with selected devices
        folder_layout = QHBoxLayout()
        self.folder_label = QLabel("No folder selected")
        self.browse_folder_btn = QPushButton("Browse Folder to Share")
        self.browse_folder_btn.clicked.connect(self.browse_folder_to_share)
        folder_layout.addWidget(self.folder_label)
        folder_layout.addWidget(self.browse_folder_btn)
        layout.addLayout(folder_layout)

        # Device discovery list
        self.device_list = QListWidget()
        layout.addWidget(QLabel("Discovered Devices:"))
        layout.addWidget(self.device_list)

        # Device permission management button
        self.permission_btn = QPushButton("Manage Device Permissions")
        self.permission_btn.clicked.connect(self.open_permission_dialog)
        layout.addWidget(self.permission_btn)

        central_widget.setLayout(layout)

    def open_permission_dialog(self):
        # Implement a simple device permission management dialog
        from PyQt5.QtWidgets import QDialog, QVBoxLayout, QListWidget, QListWidgetItem, QPushButton, QHBoxLayout

        class DevicePermissionDialog(QDialog):
            def __init__(self, parent, known_devices):
                super().__init__(parent)
                self.setWindowTitle("Device Permission Management")
                self.resize(400, 300)
                self.known_devices = known_devices
                self.layout = QVBoxLayout()
                self.list_widget = QListWidget()
                self.layout.addWidget(self.list_widget)

                # Populate list with devices and checkboxes
                for ip, info in self.known_devices.items():
                    item = QListWidgetItem(f"{info['name']} - {ip}")
                    item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                    item.setCheckState(Qt.Checked if info.get("enabled", True) else Qt.Unchecked)
                    self.list_widget.addItem(item)

                # Buttons
                btn_layout = QHBoxLayout()
                self.save_btn = QPushButton("Save")
                self.cancel_btn = QPushButton("Cancel")
                btn_layout.addWidget(self.save_btn)
                btn_layout.addWidget(self.cancel_btn)
                self.layout.addLayout(btn_layout)

                self.setLayout(self.layout)

                self.save_btn.clicked.connect(self.accept)
                self.cancel_btn.clicked.connect(self.reject)

            def get_permissions(self):
                permissions = {}
                for i in range(self.list_widget.count()):
                    item = self.list_widget.item(i)
                    ip = list(self.known_devices.keys())[i]
                    enabled = item.checkState() == Qt.Checked
                    permissions[ip] = enabled
                return permissions

        dialog = DevicePermissionDialog(self, self.known_devices)
        if dialog.exec_() == QDialog.Accepted:
            permissions = dialog.get_permissions()
            # Update known_devices enabled status
            for ip, enabled in permissions.items():
                self.known_devices[ip]["enabled"] = enabled
            # Update allowed devices in FTP handler
            self.update_allowed_devices()

    def update_allowed_devices(self):
        # Update the allowed_devices set in PermissionFTPHandler based on enabled devices
        allowed = {ip for ip, info in self.known_devices.items() if info.get("enabled", False)}
        ftp_core.PermissionFTPHandler.allowed_devices = allowed

    def on_device_clicked(self, item):
        # Extract device name and IP from item text
        text = item.text()
        if " - " in text:
            name, ip = text.split(" - ", 1)
        else:
            ip = text
        # Open file dialog to select file to share
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Share")
        if not file_path:
            return
        # Show waiting dialog for receiver permission
        from PyQt5.QtWidgets import QMessageBox
        waiting_msg = QMessageBox(self)
        waiting_msg.setWindowTitle("Waiting for Permission")
        waiting_msg.setText(f"Waiting for {name} to accept the file transfer...")
        waiting_msg.setStandardButtons(QMessageBox.NoButton)
        waiting_msg.show()
        # Perform FTP upload in a separate thread to avoid blocking UI
        import threading
        def upload_file():
            from ftplib import FTP, error_perm, all_errors
            try:
                ftp = FTP(ip, timeout=10)
                ftp.login(user=self.username_input.text(), passwd=self.password_input.text())
                with open(file_path, "rb") as f:
                    ftp.storbinary(f"STOR {os.path.basename(file_path)}", f)
                ftp.quit()
                waiting_msg.accept()
                QMessageBox.information(self, "Success", "File transfer done.")
            except error_perm as e:
                waiting_msg.accept()
                QMessageBox.critical(self, "Permission Denied", f"Permission denied: {e}")
            except all_errors as e:
                waiting_msg.accept()
                QMessageBox.critical(self, "Error", f"File transfer failed: {e}")
        threading.Thread(target=upload_file).start()

    def browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Directory", self.directory)
        if dir_path:
            self.directory = dir_path
            self.dir_label.setText(f"Shared Directory: {self.directory}")

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Secured Wireless FTP Server")
        self.resize(600, 400)

        self.directory = os.getcwd()
        self.ftp_thread = None

        # Known devices dictionary: {ip: {"name": str, "enabled": bool}}
        self.known_devices = {}

        # Mapping device IP to list of allowed folders
        self.device_allowed_folders = {}

        # Device discovery
        self.device_discovery = DeviceDiscovery()
        self.device_discovery.device_found.connect(self.on_device_found)
        self.device_discovery.device_removed.connect(self.on_device_removed)

        # Timer to check permission queue
        self.permission_timer = QTimer()
        self.permission_timer.timeout.connect(self.check_permission_queue)
        self.permission_timer.start(500)  # check every 500 ms

        # Timer to check client event queue
        self.client_timer = QTimer()
        self.client_timer.timeout.connect(self.check_client_event_queue)
        self.client_timer.start(500)  # check every 500 ms

        self.init_ui()

    def browse_folder_to_share(self):
        from PyQt5.QtWidgets import QMessageBox
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Share")
        if folder_path:
            self.folder_label.setText(folder_path)
            selected_items = self.permanent_client_list.selectedItems()
            if not selected_items:
                QMessageBox.warning(self, "No Devices Selected", "Please select one or more devices to share the folder with.")
                return
            selected_ips = [item.text().split(" - ")[-1] for item in selected_items]
            # Update device_allowed_folders mapping
            for ip in selected_ips:
                if ip not in self.device_allowed_folders:
                    self.device_allowed_folders[ip] = []
                if folder_path not in self.device_allowed_folders[ip]:
                    self.device_allowed_folders[ip].append(folder_path)
            # Update PermissionFTPHandler.device_permissions accordingly
            ftp_core.PermissionFTPHandler.device_permissions = self.device_allowed_folders
            print(f"Sharing folder '{folder_path}' with devices: {selected_ips}")

    def start_server(self):
        if self.ftp_thread and self.ftp_thread.isRunning():
            self.statusBar().showMessage("Server already running")
            return
        username = self.username_input.text()
        password = self.password_input.text()
        self.ftp_thread = FTPServerThread(self.directory, username, password)
        self.ftp_thread.server_started.connect(self.on_server_started)
        self.ftp_thread.server_stopped.connect(self.on_server_stopped)
        self.ftp_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.statusBar().showMessage("Starting server...")

    def stop_server(self):
        if self.ftp_thread:
            self.ftp_thread.stop()
            self.ftp_thread.wait()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.statusBar().showMessage("Server stopped")

    def on_server_started(self):
        self.statusBar().showMessage("FTP Server running")
        # Display local IP and port
        import socket
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        self.address_label.setText(f"FTP Server Address: ftp://{local_ip}:2121")

    def on_server_stopped(self):
        self.statusBar().showMessage("FTP Server stopped")
        self.address_label.setText("FTP Server Address: Not running")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.client_list.clear()
        self.client_list.addItem("No clients connected")

    def on_device_found(self, name, address):
        # Add device to known_devices if not present
        if address not in self.known_devices:
            self.known_devices[address] = {"name": name, "enabled": True}
            # No longer update allowed devices since connection is unrestricted
            # self.update_allowed_devices()
        # Update device list UI
        self.device_list.addItem(f"{name} - {address}")

    def on_device_removed(self, name):
        # Optionally update device list UI on device removal
        for i in range(self.device_list.count()):
            if self.device_list.item(i).text().startswith(name):
                self.device_list.takeItem(i)
                break

    def closeEvent(self, event):
        self.device_discovery.close()
        event.accept()

    def check_permission_queue(self):
        try:
            # Updated to handle device IP in permission requests
            data = ftp_core.permission_queue.get_nowait()
        except:
            return
        if len(data) == 3:
            operation, device_ip, filename = data
        else:
            # fallback for old format
            operation, filename = data
            device_ip = None
        # Here you can implement a custom dialog or logic to check device-specific permissions
        # For now, we use the existing PermissionDialog for simplicity
        dialog = PermissionDialog(filename, operation, self)
        result = dialog.exec_()
        allowed = dialog.result
        # Update the device permissions mapping if allowed
        if allowed and device_ip:
            perms = ftp_core.PermissionFTPHandler.device_permissions.get(device_ip, set())
            perms.add(filename)
            ftp_core.PermissionFTPHandler.device_permissions[device_ip] = perms
        ftp_core.permission_queue.put(allowed)

    def check_client_event_queue(self):
        try:
            event, ip = ftp_core.client_event_queue.get_nowait()
        except:
            return
        if event == "connect":
            self.add_client(ip)
            # Add to permanent client device list if not present
            if not any(self.permanent_client_list.item(i).text().endswith(ip) for i in range(self.permanent_client_list.count())):
                self.permanent_client_list.addItem(f"Device - {ip}")
        elif event == "disconnect":
            self.remove_client(ip)

    def add_client(self, ip):
        # Add client IP to the list if not already present
        for i in range(self.client_list.count()):
            if self.client_list.item(i).text() == ip:
                return
        if self.client_list.count() == 1 and self.client_list.item(0).text() == "No clients connected":
            self.client_list.clear()
        self.client_list.addItem(ip)

    def remove_client(self, ip):
        for i in range(self.client_list.count()):
            if self.client_list.item(i).text() == ip:
                self.client_list.takeItem(i)
                break
        if self.client_list.count() == 0:
            self.client_list.addItem("No clients connected")

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
