import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os

# Interfaz realizada con Tkinter
root = tk.Tk()
root.title("Aplicación Criptográfica Simétrica")
root.geometry("400x200")

def select_file():
    """Selecciona un archivo."""
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def encrypt():
    """Ejecuta cifrado."""
    file_path = entry_file.get()
    password = entry_password.get()
    if file_path and password:
        try:
            encrypted_path = encrypt_file(file_path, password)
            messagebox.showinfo("Éxito", f"Archivo cifrado: {encrypted_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Advertencia", "Selecciona un archivo e ingresa una contraseña.")

def decrypt():
    """Ejecuta descifrado."""
    file_path = entry_file.get()
    password = entry_password.get()
    if file_path and password:
        try:
            decrypted_path = decrypt_file(file_path, password)
            messagebox.showinfo("Éxito", f"Archivo descifrado: {decrypted_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Advertencia", "Selecciona un archivo e ingresa una contraseña.")

# Elementos de la GUI
label_file = tk.Label(root, text="Archivo:")
label_file.pack()
entry_file = tk.Entry(root, width=50)
entry_file.pack()
button_select = tk.Button(root, text="Seleccionar Archivo", command=select_file)
button_select.pack()

label_password = tk.Label(root, text="Contraseña:")
label_password.pack()
entry_password = tk.Entry(root, show="*", width=50)
entry_password.pack()

button_encrypt = tk.Button(root, text="Cifrar", command=encrypt)
button_encrypt.pack()
button_decrypt = tk.Button(root, text="Descifrar", command=decrypt)
button_decrypt.pack()

root.mainloop()