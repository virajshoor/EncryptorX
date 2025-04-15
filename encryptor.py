import base64
import os
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


class TextEncryptor:
    """
    A class to encrypt and decrypt text messages using enhanced AES encryption.
    """
    
    # Number of iterations for key derivation
    KDF_ITERATIONS = 100000
    
    @staticmethod
    def derive_key(password, salt=None):
        """
        Derive a cryptographic key from a password using PBKDF2.
        
        Args:
            password (str or bytes): The password
            salt (bytes, optional): Salt for key derivation, generated if None
            
        Returns:
            tuple: (derived_key, salt)
        """
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        # Generate a random salt if not provided
        if salt is None:
            salt = os.urandom(16)
            
        # Use PBKDF2 to derive a secure key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits for AES-256
            salt=salt,
            iterations=TextEncryptor.KDF_ITERATIONS,
            backend=default_backend()
        )
        
        derived_key = kdf.derive(password)
        return derived_key, salt
    
    @staticmethod
    def encrypt(plaintext, password):
        """
        Encrypt the plaintext using AES-256-CBC with authentication.
        
        Args:
            plaintext (str): The text to encrypt
            password (str): The password for encryption
            
        Returns:
            str: Encrypted data as a base64 encoded string
        """
        if not password:
            raise ValueError("Password is required for encryption")
            
        # Generate a random IV (Initialization Vector)
        iv = os.urandom(16)
        
        # Generate a random salt and derive key
        key, salt = TextEncryptor.derive_key(password)
        
        # Convert plaintext to bytes
        plaintext_bytes = plaintext.encode('utf-8')
        
        # Pad the plaintext to be a multiple of block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext_bytes) + padder.finalize()
        
        # Create the cipher with AES-256-CBC
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        # Encrypt the padded data
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # Create HMAC for authentication
        h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
        h.update(iv + salt + ciphertext)
        hmac_digest = h.finalize()
        
        # Pack everything into a single binary blob
        # Format: IV (16 bytes) + Salt (16 bytes) + HMAC (32 bytes) + Ciphertext (variable)
        encrypted_data = iv + salt + hmac_digest + ciphertext
        
        # Encode as base64 for easier handling
        # This creates a random-looking string
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    @staticmethod
    def decrypt(encrypted_data, password):
        """
        Decrypt the encrypted text.
        
        Args:
            encrypted_data (str): The base64 encoded encrypted data
            password (str): The password for decryption
            
        Returns:
            str: The decrypted plaintext
        """
        try:
            # Decode from base64
            binary_data = base64.b64decode(encrypted_data)
            
            # Extract components
            # First 16 bytes are IV
            iv = binary_data[:16]
            # Next 16 bytes are salt
            salt = binary_data[16:32]
            # Next 32 bytes are HMAC
            hmac_digest = binary_data[32:64]
            # The rest is ciphertext
            ciphertext = binary_data[64:]
            
            # Derive the key from the password and salt
            key, _ = TextEncryptor.derive_key(password, salt)
            
            # Verify HMAC first (authenticate-then-decrypt)
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(iv + salt + ciphertext)
            try:
                h.verify(hmac_digest)
            except Exception:
                raise ValueError("Message authentication failed: data may have been tampered with or incorrect password")
            
            # Create the cipher for decryption
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            
            # Decrypt the ciphertext
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Unpad the decrypted data
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            plaintext_bytes = unpadder.update(padded_data) + unpadder.finalize()
            
            # Return the decrypted plaintext as string
            return plaintext_bytes.decode('utf-8')
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")


class EncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Text Encryption Tool")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Create encryption tab
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text="Encrypt")
        self._setup_encrypt_tab()
        
        # Create decryption tab
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text="Decrypt")
        self._setup_decrypt_tab()
    
    def _setup_encrypt_tab(self):
        # Input frame
        input_frame = ttk.LabelFrame(self.encrypt_frame, text="Input")
        input_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Message input
        ttk.Label(input_frame, text="Message to encrypt:").pack(anchor="w", padx=5, pady=5)
        self.encrypt_input = scrolledtext.ScrolledText(input_frame, height=6)
        self.encrypt_input.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Password input
        password_frame = ttk.LabelFrame(input_frame, text="Password")
        password_frame.pack(fill="x", padx=5, pady=5)
        
        self.password_entry = ttk.Entry(password_frame, show="*")
        self.password_entry.pack(fill="x", expand=True, padx=5, pady=5)
        
        self.show_encrypt_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(password_frame, text="Show password", 
                       variable=self.show_encrypt_password_var, 
                       command=self.toggle_encrypt_password).pack(anchor="w", padx=5)
        
        # Buttons
        button_frame = ttk.Frame(self.encrypt_frame)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text="Encrypt", command=self.encrypt_message).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_encrypt).pack(side="left", padx=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(self.encrypt_frame, text="Output")
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Encrypted text output
        ttk.Label(output_frame, text="Encrypted data:").pack(anchor="w", padx=5, pady=2)
        self.encrypt_output = scrolledtext.ScrolledText(output_frame, height=6)
        self.encrypt_output.config(state='disabled')  # Make it read-only
        self.encrypt_output.pack(fill="both", expand=True, padx=5, pady=2)
        ttk.Button(output_frame, text="Copy Encrypted Data", 
                  command=lambda: self.copy_to_clipboard(self.encrypt_output)).pack(anchor="e", padx=5, pady=2)
    
    def toggle_encrypt_password(self):
        if self.show_encrypt_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def _setup_decrypt_tab(self):
        # Input frame
        input_frame = ttk.LabelFrame(self.decrypt_frame, text="Input")
        input_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Encrypted message input
        ttk.Label(input_frame, text="Encrypted data:").pack(anchor="w", padx=5, pady=2)
        self.decrypt_input = scrolledtext.ScrolledText(input_frame, height=4)
        self.decrypt_input.pack(fill="both", expand=True, padx=5, pady=2)
        
        # Password input
        password_frame = ttk.LabelFrame(input_frame, text="Password")
        password_frame.pack(fill="x", padx=5, pady=5)
        
        self.decrypt_password_entry = ttk.Entry(password_frame, show="*")
        self.decrypt_password_entry.pack(fill="x", expand=True, padx=5, pady=5)
        
        # Show password checkbox
        self.show_decrypt_password_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(password_frame, text="Show password", 
                       variable=self.show_decrypt_password_var, 
                       command=self.toggle_decrypt_password).pack(anchor="w", padx=5)
        
        # Buttons
        button_frame = ttk.Frame(self.decrypt_frame)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text="Decrypt", command=self.decrypt_message).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_decrypt).pack(side="left", padx=5)
        
        # Output frame
        output_frame = ttk.LabelFrame(self.decrypt_frame, text="Decrypted Message")
        output_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Decrypted text output
        self.decrypt_output = scrolledtext.ScrolledText(output_frame)
        self.decrypt_output.config(state='disabled')  # Make it read-only
        self.decrypt_output.pack(fill="both", expand=True, padx=5, pady=5)
        ttk.Button(output_frame, text="Copy Decrypted Message", 
                  command=lambda: self.copy_to_clipboard(self.decrypt_output)).pack(anchor="e", padx=5, pady=2)
    
    def toggle_decrypt_password(self):
        if self.show_decrypt_password_var.get():
            self.decrypt_password_entry.config(show="")
        else:
            self.decrypt_password_entry.config(show="*")
    
    def encrypt_message(self):
        plaintext = self.encrypt_input.get("1.0", "end-1c").strip()
        password = self.password_entry.get()
        
        if not plaintext:
            messagebox.showwarning("Warning", "Please enter a message to encrypt.")
            return
            
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
        
        try:
            encrypted = TextEncryptor.encrypt(plaintext, password)
            self.encrypt_output.config(state='normal')  # Temporarily enable editing
            self.encrypt_output.delete("1.0", tk.END)
            self.encrypt_output.insert("1.0", encrypted)
            self.encrypt_output.config(state='disabled')  # Make read-only again
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_message(self):
        encrypted_text = self.decrypt_input.get("1.0", "end-1c").strip()
        password = self.decrypt_password_entry.get()
        
        if not encrypted_text:
            messagebox.showwarning("Warning", "Please enter encrypted data.")
            return
            
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
        
        try:
            decrypted = TextEncryptor.decrypt(encrypted_text, password)
            self.decrypt_output.config(state='normal')  # Temporarily enable editing
            self.decrypt_output.delete("1.0", tk.END)
            self.decrypt_output.insert("1.0", decrypted)
            self.decrypt_output.config(state='disabled')  # Make read-only again
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")
    
    def copy_to_clipboard(self, text_widget):
        text = text_widget.get("1.0", "end-1c")
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            messagebox.showinfo("Copied", "Content copied to clipboard.")
    
    def clear_encrypt(self):
        self.encrypt_input.delete("1.0", tk.END)
        self.encrypt_output.config(state='normal')  # Temporarily enable editing
        self.encrypt_output.delete("1.0", tk.END)
        self.encrypt_output.config(state='disabled')  # Make read-only again
        self.password_entry.delete(0, tk.END)
    
    def clear_decrypt(self):
        self.decrypt_input.delete("1.0", tk.END)
        self.decrypt_password_entry.delete(0, tk.END)
        self.decrypt_output.config(state='normal')  # Temporarily enable editing
        self.decrypt_output.delete("1.0", tk.END)
        self.decrypt_output.config(state='disabled')  # Make read-only again


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptorApp(root)
    root.mainloop()