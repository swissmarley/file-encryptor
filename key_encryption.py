import os
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk 
from cryptography.fernet import Fernet

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Encryptor V2")

        image_path = os.path.join(os.path.dirname(__file__), 'src', 'logo.png')
        logo_image = Image.open(image_path)
        logo_image = logo_image.resize((100, 100)) 
        self.logo_icon = ImageTk.PhotoImage(logo_image)
        self.master.iconphoto(True, self.logo_icon)

        self.logo_label = tk.Label(self.master, image=self.logo_icon)
        self.logo_label.pack(side="top", pady=10)

        self.label = tk.Label(master, text="Select File or Folder:")
        self.label.pack(pady=10)

        self.path_label = tk.Label(master, text="")
        self.path_label.pack(pady=5)

        self.browse_file_button = tk.Button(master, text="Browse File", command=self.browse_file)
        self.browse_file_button.pack(side="left", padx=10, pady=10)

        self.browse_folder_button = tk.Button(master, text="Browse Folder", command=self.browse_folder)
        self.browse_folder_button.pack(side="right", padx=10, pady=10)

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack(pady=5)

        self.key = None

    def generate_key(self):
        key_file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])

        if not key_file_path:
            tk.messagebox.showwarning("Key File Not Selected", "Key file not selected. Encryption and decryption won't work.")
            return

        self.key_file = key_file_path

        if os.path.exists(key_file_path):
            with open(key_file_path, "rb") as key_file:
                self.key = key_file.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file_path, "wb") as key_file:
                key_file.write(self.key)

    def load_key(self):
        key_file_path = filedialog.askopenfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])

        if not key_file_path:
            tk.messagebox.showwarning("Key File Not Selected", "Key file not selected. Encryption and decryption won't work.")
            return

        self.key_file = key_file_path

        if os.path.exists(key_file_path):
            with open(key_file_path, "rb") as key_file:
                self.key = key_file.read()
        else:
            self.key = Fernet.generate_key()
            with open(key_file_path, "wb") as key_file:
                key_file.write(self.key)

    def browse_file(self):
        file_paths = filedialog.askopenfilenames()
        if file_paths:
            self.path_label.config(text="\n".join(file_paths))
            self.file_paths = file_paths

    def browse_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.path_label.config(text=folder_path)
            self.folder_path = folder_path

    def encrypt(self):
        if hasattr(self, 'file_paths') or hasattr(self, 'folder_path'):
            paths = getattr(self, 'file_paths', []) or [self.folder_path]

            for path in paths:
                if os.path.isfile(path):
                    self.encrypt_file(path)
                elif os.path.isdir(path):
                    self.encrypt_folder(path)
                else:
                    print(f"Unsupported file type: {path}")

            tk.messagebox.showinfo("Encryption Completed", "Encryption completed.")

        else:
            tk.messagebox.showwarning("No File Selected", "Please select a file or folder to encrypt.")

    def decrypt(self):
        if hasattr(self, 'file_paths') or hasattr(self, 'folder_path'):
            paths = getattr(self, 'file_paths', []) or [self.folder_path]

            for path in paths:
                if os.path.isfile(path):
                    self.decrypt_file(path)
                elif os.path.isdir(path):
                    self.decrypt_folder(path)
                else:
                    print(f"Unsupported file type: {path}")

            tk.messagebox.showinfo("Decryption Completed", "Decryption completed.")

        else:
            tk.messagebox.showwarning("No File Selected", "Please select a file or folder to decrypt.")

    def encrypt_file(self, file_path):
        with open(file_path, 'rb') as file:
            data = file.read()

        if self.key is None:
            self.generate_key()

        encrypted_filename = Fernet(self.key).encrypt(os.path.basename(file_path).encode()).decode()
        encrypted_file_path = os.path.join(os.path.dirname(file_path), encrypted_filename + ".encrypted")
        
        cipher_suite = Fernet(self.key)
        encrypted_data = cipher_suite.encrypt(data)

        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        os.remove(file_path)

    def decrypt_file(self, file_path):
        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        if self.key is None:
            self.load_key()

        try:
            cipher_suite = Fernet(self.key)
            decrypted_data = cipher_suite.decrypt(encrypted_data)
        except Exception as e:
            print(f"Error decrypting file: {file_path}")
            print(f"Encrypted data: {encrypted_data}")
            print(f"Error message: {str(e)}")
            return

        decrypted_filename = Fernet(self.key).decrypt(os.path.basename(file_path)[:-10].encode()).decode()
        decrypted_file_path = os.path.join(os.path.dirname(file_path), decrypted_filename)

        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        os.remove(file_path) 

    def encrypt_folder(self, folder_path):
        if self.key is None:
            self.generate_key()

        encrypted_folder_name = Fernet(self.key).encrypt(os.path.basename(folder_path).encode()).decode()
        encrypted_folder_path = os.path.join(os.path.dirname(folder_path), encrypted_folder_name + ".encrypted")

        os.rename(folder_path, encrypted_folder_path)

        for root, dirs, files in os.walk(encrypted_folder_path):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                self.encrypt_folder(dir_path)

            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.encrypt_file(file_path)

    def decrypt_folder(self, folder_path):
        if self.key is None:
            self.load_key()

        decrypted_folder_name = Fernet(self.key).decrypt(os.path.basename(folder_path)[:-10].encode()).decode()
        decrypted_folder_path = os.path.join(os.path.dirname(folder_path), decrypted_folder_name)

        for root, dirs, files in os.walk(folder_path):
            for dir_name in dirs:
                dir_path = os.path.join(root, dir_name)
                self.decrypt_folder(dir_path)

            for file_name in files:
                file_path = os.path.join(root, file_name)
                self.decrypt_file(file_path)

        os.rename(folder_path, decrypted_folder_path)

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
