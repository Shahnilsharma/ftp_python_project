from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QHBoxLayout

class PermissionDialog(QDialog):
    def __init__(self, filename, operation, parent=None):
        super().__init__(parent)
        self.setWindowTitle("File Transfer Permission Request")
        self.result = False

        layout = QVBoxLayout()
        message = QLabel(f"Request to {operation} file:\n{filename}\nAllow?")
        layout.addWidget(message)

        btn_layout = QHBoxLayout()
        allow_btn = QPushButton("Allow")
        deny_btn = QPushButton("Deny")
        btn_layout.addWidget(allow_btn)
        btn_layout.addWidget(deny_btn)
        layout.addLayout(btn_layout)

        allow_btn.clicked.connect(self.allow)
        deny_btn.clicked.connect(self.deny)

        self.setLayout(layout)

    def allow(self):
        self.result = True
        self.accept()

    def deny(self):
        self.result = False
        self.reject()
