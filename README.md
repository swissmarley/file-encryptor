# 🔒 Secure File Encryptor/Decryptor 🔒

Protect your sensitive files with the Secure File Encryptor/Decryptor app, a powerful and easy-to-use tool designed to secure your valuable data. Whether you're safeguarding personal documents, confidential business files, or cherished memories, this application ensures that your information remains private and secure.

<div align="center">
    <img src="https://nakyaa.files.wordpress.com/2024/02/fileencryptor-1.png?w=4000&h=" width=400>
</div>

## Key Features

- **User-Friendly Interface:** The app provides a clean and intuitive interface, allowing users to encrypt and decrypt files and folders effortlessly.
  
- **Versatile Encryption:** Utilizing advanced cryptography, the app supports both file and folder encryption. Choose between encrypting individual files or securing entire folders, including all contents and subfolders.
  
- **Password Protection:** Enhance your file security with password protection. The app employs industry-standard key derivation and encryption algorithms, ensuring that only authorized users can access your encrypted files.
  
- **Key Management:** Easily generate, save, and load encryption keys. The app gives you control over where to store your encryption key, adding an extra layer of customization to your security preferences.
  
- **Real-time Feedback:** Stay informed with real-time feedback on the encryption and decryption process. The app provides status updates, ensuring a smooth and transparent user experience.

## Versions

### Password Encryption

- **Description:** This version of the application allows users to encrypt and decrypt files and folders using a password-based approach. It employs key derivation techniques to generate encryption keys from user-provided passwords.
  
- **File:** [password_encryption.py](password_encryption.py)

### Key Encryption

- **Description:** The Key Encryption version of the application offers an alternative method for encrypting and decrypting files and folders. It utilizes secret key encryption, where users can generate, save, and load secret keys for encryption and decryption operations.
  
- **File:** [key_encryption.py](key_encryption.py)

## Getting Started

1. Clone the repository
2. Install required packages
3. Run Application

```bash
git clone https://github.com/swissmarley/file-encryptor.git
cd file-encryptor
pip install -r requirements.txt
python key_encryption.py
python password_encryption.py
```


## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
