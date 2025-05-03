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
    def on_connect(self):
        print(f"Connection from {self.remote_ip}:{self.remote_port}")
        client_event_queue.put(("connect", self.remote_ip))

    def on_disconnect(self):
        print(f"Disconnected from {self.remote_ip}:{self.remote_port}")
        client_event_queue.put(("disconnect", self.remote_ip))

    def on_login(self, username):
        print(f"User {username} logged in")

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

    def ftp_RETR(self, file):
        # Request permission before allowing download
        permission_queue.put(("RETR", file))
        allowed = permission_queue.get()  # Wait for GUI response
        if allowed:
            super().ftp_RETR(file)
        else:
            self.respond("550 Permission denied.")

    def ftp_STOR(self, file, mode='w'):
        # Request permission before allowing upload
        permission_queue.put(("STOR", file))
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
