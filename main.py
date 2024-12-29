import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QTextCursor
from functions import (
    domain_lookup, submit_file_hash, submit_website, 
    check_website_status, upload_file, check_ip, get_local_filehash_and_check
)

class VirusTotalGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle("VirusTotal API Tool")
        self.setGeometry(100, 100, 380, 860)

        # Set transparency and styling
        self.setWindowOpacity(0.95)
        palette = self.palette()
        palette.setColor(QPalette.Window, QColor(20, 20, 20))  # Darker background
        self.setPalette(palette)

        layout = QVBoxLayout()

        self.output = QTextEdit(self)
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: black; color: dodgerblue;")  # Dark theme styling
        layout.addWidget(self.output)

        buttons = [
            ("Domain Lookup", self.handle_domain_lookup),
            ("Submit File Hash", self.handle_submit_file_hash),
            ("Submit Website for Check", self.handle_submit_website),
            ("Check Website Status", self.handle_check_website_status),
            ("Upload File for Check", self.handle_upload_file),
            ("Check IP Reputation", self.handle_check_ip),
            ("Get Local Filehash and Check", self.handle_get_local_filehash_and_check),
        ]

        for text, handler in buttons:
            button = QPushButton(text, self)
            button.clicked.connect(handler)
            button.setStyleSheet("color: lime; border: 1px solid black;")  # Green text and black border
            layout.addWidget(button)

        # Add Copy to Clipboard Button
        copy_button = QPushButton("Copy to Clipboard", self)
        copy_button.clicked.connect(self.copy_to_clipboard)
        copy_button.setStyleSheet("color: lime; border: 1px solid black;")  # Green text and black border
        layout.addWidget(copy_button)

        self.setLayout(layout)

    def clear_and_append_output(self, text):
        """Clears the output field, appends new text, and resets the scroll to the top."""
        self.output.clear()
        self.output.append(text)
        self.output.moveCursor(QTextCursor.Start)  # Correct usage of QTextCursor


    def handle_domain_lookup(self):
        domain_lookup(self, self.clear_and_append_output)

    def handle_submit_file_hash(self):
        submit_file_hash(self, self.clear_and_append_output)

    def handle_submit_website(self):
        submit_website(self, self.clear_and_append_output)

    def handle_check_website_status(self):
        check_website_status(self, self.clear_and_append_output)

    def handle_upload_file(self):
        upload_file(self, self.clear_and_append_output)

    def handle_check_ip(self):
        check_ip(self, self.clear_and_append_output)

    def handle_get_local_filehash_and_check(self):
        get_local_filehash_and_check(self, self.clear_and_append_output)

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.output.toPlainText())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = VirusTotalGUI()
    window.show()
    sys.exit(app.exec_())
