# Secured Wireless FTP Server

This project implements a secured wireless FTP server with a graphical user interface (GUI) built using PyQt5. It allows users to share directories over FTP with device-specific permissions and real-time device discovery on the local network.

## Features

- **FTP Server**: Based on `pyftpdlib`, supports user authentication, anonymous access, and device-specific folder permissions.
- **Device Discovery**: Uses Zeroconf (mDNS) to discover FTP-capable devices on the local network.
- **Graphical User Interface**: PyQt5-based GUI to manage the FTP server, connected clients, device permissions, and shared folders.
- **Permission Management**: Real-time permission requests for file uploads/downloads with user approval dialogs.
- **Client Monitoring**: Displays connected clients and allows managing permanent client devices.
- **Folder Sharing**: Share specific folders with selected devices with fine-grained control.

## Components

- `device_discovery.py`: Discovers FTP devices on the local network using Zeroconf and emits signals for device found/removed.
- `ftp_core.py`: Implements the FTP server with custom permission handling per device IP and communication queues for GUI interaction.
- `ftp_gui.py`: PyQt5 GUI application to start/stop the FTP server, manage devices, permissions, and monitor clients.
- `permission_dialog.py`: Dialog window to request user permission for file transfer operations.

## Requirements

- Python 3.6+
- PyQt5
- pyftpdlib
- zeroconf

Install dependencies using pip:

```bash
pip install PyQt5 pyftpdlib zeroconf
```

## Usage

1. Run the GUI application:

```bash
python ftp_gui.py
```

2. Use the GUI to:
   - Select the directory to share.
   - Start or stop the FTP server.
   - View discovered devices and connected clients.
   - Manage device permissions and share folders with specific devices.
   - Approve or deny file transfer requests in real-time.

3. Devices on the local network advertising FTP services will be discovered automatically.

## Notes

- The FTP server listens on port 2121 by default.
- Permissions are managed per device IP address.
- The application uses PyQt signals and threads to handle asynchronous events and UI updates.
- The project is designed for local network use and assumes trusted users.

## License

This project is provided as-is under the MIT License.
