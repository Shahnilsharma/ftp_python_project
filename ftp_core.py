import os
import queue
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

# Global permission queue to communicate with GUI
permission_queue = queue.Queue()

# Global client event queue to communicate client connect/disconnect to GUI
client_event_queue = queue.Queue()

class PermissionFTPHandler(FTPHandler):
    # Mapping of device IPs to allowed files (or directories)
    device_permissions = {}

    def on_connect(self):
        print(f"Connection from {self.remote_ip}:{self.remote_port}")
        client_event_queue.put(("connect", self.remote_ip))

    def on_disconnect(self):
        print(f"Disconnected from {self.remote_ip}:{self.remote_port}")
        client_event_queue.put(("disconnect", self.remote_ip))

    def on_login(self, username):
        print(f"User {username} logged in")
        # Set root directory based on device IP permissions
        allowed_folders = self.device_permissions.get(self.remote_ip, None)
        if allowed_folders and len(allowed_folders) > 0:
            # For simplicity, set the first allowed folder as root directory
            root_dir = allowed_folders[0]
            if os.path.isdir(root_dir):
                self.abstracted_fs.root = root_dir
                self.home_dir = root_dir
                print(f"Set root directory for {self.remote_ip} to {root_dir}")
            else:
                print(f"Allowed folder {root_dir} does not exist or is not a directory")
        else:
            # No allowed folders, deny access by setting root to empty or default
            self.abstracted_fs.root = ""
            self.home_dir = ""
            print(f"No allowed folders for {self.remote_ip}, root directory set to empty")

    def on_login_failed(self, username, password):
        print(f"Failed login attempt for {username}")

    def on_file_sent(self, file):
        print(f"File sent: {file}")

    def on_file_received(self, file):
        print(f"File received: {file}")

    def on_incomplete_file_sent(self, file):
        print(f"Incomplete file sent: {file}")

    def on_incomplete_file_received(self, file):
        print(f"Incomplete file received: {file}")

    def has_permission(self, file):
        # Check if the device has permission to access the file
        allowed_files = self.device_permissions.get(self.remote_ip, None)
        if allowed_files is None:
            # If no specific permissions set, deny access by default
            return False
        # Check if file is in allowed files or allowed directory
        # For simplicity, allow if file path starts with any allowed path
        for allowed_path in allowed_files:
            if file.startswith(allowed_path):
                return True
        return False

    def ftp_RETR(self, file):
        # Check device-specific permission before allowing download
        if not self.has_permission(file):
            self.respond("550 Permission denied.")
            return
        # Request permission from GUI before allowing download
        permission_queue.put(("RETR", self.remote_ip, file))
        allowed = permission_queue.get()  # Wait for GUI response
        if allowed:
            super().ftp_RETR(file)
        else:
            self.respond("550 Permission denied.")

    def ftp_STOR(self, file, mode='w'):
        # Check device-specific permission before allowing upload
        if not self.has_permission(file):
            self.respond("550 Permission denied.")
            return
        # Request permission from GUI before allowing upload
        permission_queue.put(("STOR", self.remote_ip, file))
        allowed = permission_queue.get()  # Wait for GUI response
        if allowed:
            super().ftp_STOR(file, mode)
        else:
            self.respond("550 Permission denied.")

def main():
    authorizer = DummyAuthorizer()
    # Configure user credentials and permissions
    # 'elradfmw' = all permissions: 
    # e = change directory, l = list files, r = retrieve file, a = append data,
    # d = delete file, f = rename file, m = create directory, w = write file
    authorizer.add_user("user", "12345", os.getcwd(), perm="elradfmw")
    authorizer.add_anonymous(os.getcwd(), perm="elradfmw")

    handler = PermissionFTPHandler
    handler.authorizer = authorizer

    # Enable passive ports range
    handler.passive_ports = range(60000, 65535)

    # Create FTP server
    address = ("0.0.0.0", 2121)
    server = FTPServer(address, handler)

    print("Starting FTP server on port 2121...")
    server.serve_forever()

if __name__ == "__main__":
    main()
