import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import json
import os

root = tk.Tk()
root.title("Aplicación Criptográfica Simétrica")
root.geometry("400x200")

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def encrypt():
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
    file_path = entry_file.get()
    password = entry_password.get()
    if file_path and password:
        try:
            decrypted_path = decrypt_file(file_path, password)
            messagebox.showinfo("Éxito", f"Archivo descifrado: {decrypted_path}")
        except ValueError as e:
            if "mac check failed" in str(e).lower() or "invalid key" in str(e).lower():
                messagebox.showerror("Error", "Contraseña equivocada")
            else:
                messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Advertencia", "Selecciona un archivo e ingresa una contraseña.")

def derive_key(password, salt):
    """Deriva una clave segura con PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    """Cifra archivo con AES-GCM y metadatos."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    nonce = os.urandom(12)
    file_name = os.path.basename(file_path)
    metadata = json.dumps({'name': file_name, 'timestamp': os.path.getmtime(file_path)}).encode()
    data = len(metadata).to_bytes(4, 'big') + metadata
    
    with open(file_path, 'rb') as f:
        content = f.read()
    data += content
    
    cipher = AESGCM(key)
    encrypted = cipher.encrypt(nonce, data, None)
    
    encrypted_path = file_path + '.enc'
    with open(encrypted_path, 'wb') as f:
        f.write(salt + nonce + encrypted)
    
    return encrypted_path

def decrypt_file(file_path, password):
    """Descifra archivo con AES-GCM."""
    if len(data := open(file_path, 'rb').read()) < 28:  # salt(16) + nonce(12)
        raise ValueError("Archivo inválido")
    
    salt = data[:16]
    nonce = data[16:28]
    encrypted = data[28:]
    
    key = derive_key(password, salt)
    cipher = AESGCM(key)
    decrypted = cipher.decrypt(nonce, encrypted, None)
    
    meta_len = int.from_bytes(decrypted[:4], 'big')
    metadata = json.loads(decrypted[4:4+meta_len].decode())
    content = decrypted[4+meta_len:]
    
    output_dir = os.path.dirname(file_path)
    original_name = metadata['name']
    decrypted_path = os.path.join(output_dir, f"decrypted_{original_name}")
    print(f"Intentando escribir en: {decrypted_path} con tamaño {len(content)} bytes")
    try:
        with open(decrypted_path, 'wb') as f:
            bytes_written = f.write(content)
        print(f"Escrito {bytes_written} bytes. Archivo existe: {os.path.exists(decrypted_path)}")
        print(f"Contenido descifrado: {content.decode('utf-8', errors='ignore')}")
        with open(decrypted_path, 'rb') as f:
            written_content = f.read()
        print(f"Contenido escrito: {written_content.decode('utf-8', errors='ignore')}")
        if bytes_written == 0:
            raise ValueError("No se escribió contenido")
    except IOError as e:
        raise ValueError(f"Error al escribir el archivo: {e}")
    
    return decrypted_path

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