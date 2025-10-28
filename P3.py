import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import json
import os

root = tk.Tk()
root.title("Aplicación Criptográfica Híbrida")
root.geometry("500x300")

def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_file.delete(0, tk.END)
        entry_file.insert(0, file_path)

def select_public_key():
    key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if key_path:
        entry_public_key.delete(0, tk.END)
        entry_public_key.insert(0, key_path)

def select_private_key():
    key_path = filedialog.askopenfilename(filetypes=[("PEM files", "*.pem")])
    if key_path:
        entry_private_key.delete(0, tk.END)
        entry_private_key.insert(0, key_path)

#Funcion para P3
def generate_rsa_keys():
    try:
        generate_rsa_key_pair()
        messagebox.showinfo("Éxito", "Claves RSA generadas: private.pem y public.pem")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def encrypt():
    file_path = entry_file.get()
    password = entry_password.get()
    public_key_path = entry_public_key.get()
    if file_path and password and public_key_path:
        try:
            encrypted_path, encrypted_key_path = encrypt_file(file_path, password, public_key_path)
            messagebox.showinfo("Éxito", f"Archivo cifrado: {encrypted_path}\nClave cifrada: {encrypted_key_path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Advertencia", "Selecciona un archivo, ingresa una contraseña y selecciona la clave pública.")

def decrypt():
    file_path = entry_file.get()
    password = entry_password.get()
    private_key_path = entry_private_key.get()
    if file_path and password and private_key_path:
        try:
            # Asumir que la clave cifrada está en el mismo directorio con extensión .key.enc
            encrypted_key_path = file_path.replace('.enc', '.key.enc')
            decrypted_path = decrypt_file(file_path, encrypted_key_path, private_key_path, password)
            messagebox.showinfo("Éxito", f"Archivo descifrado: {decrypted_path}")
        except ValueError as e:
            if "mac check failed" in str(e).lower() or "invalid key" in str(e).lower():
                messagebox.showerror("Error", "Contraseña equivocada")
            else:
                messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", str(e))
    else:
        messagebox.showwarning("Advertencia", "Selecciona un archivo, ingresa una contraseña y selecciona la clave privada.")

def derive_key(password, salt):
    """Deriva una clave segura con PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

#Funcion para P3(generar keys publicas y privadas)
def generate_rsa_key_pair(private_key_path='private.pem', public_key_path='public.pem'):
    """Genera un par de claves RSA y las guarda en archivos PEM."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Guardar clave privada
    with open(private_key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Guardar clave pública
    public_key = private_key.public_key()
    with open(public_key_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

#Funcion modificada para P3
def encrypt_file(file_path, password, public_key_path):
    """Cifra archivo con AES-GCM, deriva clave simétrica y la cifra con RSA."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    
    # Cargar clave pública RSA
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    
    # Cifrar la clave simétrica con RSA-OAEP
    encrypted_key = public_key.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Almacenar la clave simétrica cifrada
    encrypted_key_path = file_path + '.key.enc'
    with open(encrypted_key_path, 'wb') as f:
        f.write(salt + encrypted_key)
    
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
        f.write(nonce + encrypted)  # Nota: salt ahora está en el archivo de clave cifrada, no aquí
    
    return encrypted_path, encrypted_key_path

#Funcion modificada para P3
def decrypt_file(file_path, encrypted_key_path, private_key_path, password):
    """Descifra la clave simétrica con RSA y luego descifra el archivo con AES-GCM."""
    # Cargar clave privada RSA
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # Leer la clave simétrica cifrada
    with open(encrypted_key_path, 'rb') as f:
        key_data = f.read()
    salt = key_data[:16]
    encrypted_key = key_data[16:]
    
    # Descifrar la clave simétrica con RSA-OAEP
    key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Verificar que la clave derivada de la contraseña coincida (opcional, pero para consistencia)
    derived_key = derive_key(password, salt)
    if key != derived_key:
        raise ValueError("Clave derivada no coincide")
    
    # Ahora descifrar el archivo
    with open(file_path, 'rb') as f:
        data = f.read()
    if len(data) < 12:
        raise ValueError("Archivo inválido")
    
    nonce = data[:12]
    encrypted = data[12:]
    
    cipher = AESGCM(key)
    decrypted = cipher.decrypt(nonce, encrypted, None)
    
    meta_len = int.from_bytes(decrypted[:4], 'big')
    metadata = json.loads(decrypted[4:4+meta_len].decode())
    content = decrypted[4+meta_len:]
    
    output_dir = os.path.dirname(file_path)
    original_name = metadata['name']
    decrypted_path = os.path.join(output_dir, f"decrypted_{original_name}")
    
    with open(decrypted_path, 'wb') as f:
        f.write(content)
    
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

label_public_key = tk.Label(root, text="Clave Pública (para cifrado):")
label_public_key.pack()
entry_public_key = tk.Entry(root, width=50)
entry_public_key.pack()
button_select_public = tk.Button(root, text="Seleccionar Clave Pública", command=select_public_key)
button_select_public.pack()

label_private_key = tk.Label(root, text="Clave Privada (para descifrado):")
label_private_key.pack()
entry_private_key = tk.Entry(root, width=50)
entry_private_key.pack()
button_select_private = tk.Button(root, text="Seleccionar Clave Privada", command=select_private_key)
button_select_private.pack()

button_generate_keys = tk.Button(root, text="Generar Claves RSA", command=generate_rsa_keys)
button_generate_keys.pack()

button_encrypt = tk.Button(root, text="Cifrar", command=encrypt)
button_encrypt.pack()
button_decrypt = tk.Button(root, text="Descifrar", command=decrypt)
button_decrypt.pack()

root.mainloop()