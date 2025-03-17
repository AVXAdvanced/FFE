import sys
import os
import json
import requests
from cryptography.fernet import Fernet
from PyQt6.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QVBoxLayout, QHBoxLayout, QFileDialog, QMessageBox, QSpacerItem, QSizePolicy
)
from PyQt6.QtGui import QFont, QPalette, QColor
from PyQt6.QtCore import Qt


class FFEApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.initEncryptionSystem()

    def initUI(self):
        self.setWindowTitle("FFE - Friend File Encryptor")
        self.resize(600, 400)
        self.setStyleSheet("background-color: #121212; color: #FFFFFF;")

        title_label = QLabel("FFE")
        title_label.setFont(QFont("Arial", 64, QFont.Weight.Bold))
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        button_layout = QVBoxLayout()

        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.setStyleSheet("background-color: #3d3d3d; padding: 35px;")
        self.encrypt_button.clicked.connect(self.encrypt_action)
        button_layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.setStyleSheet("background-color: #3d3d3d; padding: 35px;")
        self.decrypt_button.clicked.connect(self.decrypt_action)
        button_layout.addWidget(self.decrypt_button)

        self.help_button = QPushButton("Help")
        self.help_button.setStyleSheet("background-color: #3d3d3d; padding: 14px;")
        self.help_button.clicked.connect(self.help_action)
        button_layout.addWidget(self.help_button)

        self.about_button = QPushButton("About")
        self.about_button.setStyleSheet("background-color: #3d3d3d; padding: 14px;")
        self.about_button.clicked.connect(self.about_action)
        button_layout.addWidget(self.about_button)

        button_layout.addSpacerItem(QSpacerItem(20, 20, QSizePolicy.Policy.Minimum, QSizePolicy.Policy.Expanding))

        self.exit_button = QPushButton("Exit")
        self.exit_button.setStyleSheet("background-color: #d91818; padding: 14px;")
        self.exit_button.clicked.connect(self.close)
        button_layout.addWidget(self.exit_button)

        button_layout.addStretch()

        main_layout = QHBoxLayout()
        main_layout.addWidget(title_label, 3)
        main_layout.addLayout(button_layout, 2)

        self.setLayout(main_layout)

    def initEncryptionSystem(self):
        if not os.path.exists("main_key.key"):
            key = Fernet.generate_key()
            with open("main_key.key", "wb") as key_file:
                key_file.write(key)
        self.main_key = self.load_key("main_key.key")
        self.keys = [self.main_key] + self.load_keys()
        self.cipher = Fernet(self.main_key)

    def load_key(self, filename):
        with open(filename, "rb") as key_file:
            return key_file.read()

    def load_keys(self):
        if os.path.exists("keys.json"):
            with open("keys.json", "r") as keys_file:
                return json.load(keys_file)
        return []

    def encrypt_action(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    file_data = file.read()
                encrypted_file_path = file_path + ".enc"
                encrypted_data = self.cipher.encrypt(file_data)
                with open(encrypted_file_path, "wb") as encrypted_file:
                    encrypted_file.write(encrypted_data)
                QMessageBox.information(self, "Success", "File Successfully Encrypted!")
            except Exception as e:
                QMessageBox.critical(self, "Error", "Encryption Failed. Try Again.")

    def decrypt_action(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select .enc File to Decrypt")
        if file_path:
            if not file_path.endswith(".enc"):
                QMessageBox.warning(self, "Error", "Selected file is not a .enc file.")
                return
            try:
                with open(file_path, "rb") as encrypted_file:
                    encrypted_data = encrypted_file.read()
                for key in self.keys:
                    cipher = Fernet(key)
                    try:
                        decrypted_data = cipher.decrypt(encrypted_data)
                        decrypted_file_path = file_path[:-4]
                        with open(decrypted_file_path, "wb") as decrypted_file:
                            decrypted_file.write(decrypted_data)
                        QMessageBox.information(self, "Success", "File Successfully Decrypted!")
                        return
                    except Exception:
                        continue
                QMessageBox.warning(self, "Error", "Decryption failed. Incorrect key.")
            except Exception as e:
                QMessageBox.critical(self, "Error", "Decryption Failed. Try Again.")

    def help_action(self):
        QMessageBox.information(self, "Help", "Visit github.com/AVXAdvanced/FFE for help and support.")

    def about_action(self):
        QMessageBox.information(self, "About", 
                                
        """FFE - Friend File Encryptor

Version 2.0.0 (IDB)
Build FFE03162025LYNA

(c)2025 AVX_Advanced
All Rights Reserved.
        """)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor(18, 18, 18))
    palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
    app.setPalette(palette)

    window = FFEApp()
    window.show()

    sys.exit(app.exec())
