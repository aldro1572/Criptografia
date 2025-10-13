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
            encrypted_path = encrypt_file(file_path, password) #Llama a la función de cifrado
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
            decrypted_path = decrypt_file(file_path, password) #Llama a la función de descifrado
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
    kdf = PBKDF2HMAC(     #Creción del objeto KDF PBKDF2
        algorithm=hashes.SHA256(), #Uso de SHA-256
        length=32,          #Clave de 256 bits para AES-256
        salt=salt,          #Sal aleatoria
        iterations=100000,  #Número de iteraciones
    )
    return kdf.derive(password.encode())      #Deriva la clave a partir de la contraseña

def encrypt_file(file_path, password):
    """Cifra archivo con AES-GCM y metadatos."""
    salt = os.urandom(16)    #Genera una sal aleatoria de 16 bytes   
    key = derive_key(password, salt)    #Deriva la clave usando la contraseña y la sal
    nonce = os.urandom(12)              #Genera un nonce aleatorio de 12 bytes para AES-GCM(debe ser único)
    file_name = os.path.basename(file_path)  
    #Crea metadatos en formato JSON
    metadata = json.dumps({'name': file_name, 'timestamp': os.path.getmtime(file_path)}).encode() 
    data = len(metadata).to_bytes(4, 'big') + metadata  #Prefija 4 bytes con la longitud de los metadatos(big-endian)
    #Lee el contenido del archivo(en la RAM)
    with open(file_path, 'rb') as f:
        content = f.read()
    data += content         #Concatena metadatos y contenido
    
    cipher = AESGCM(key)    #Cifrado AES-GCM
    encrypted = cipher.encrypt(nonce, data, None) #Cifra los datos
    
    encrypted_path = file_path + '.enc'
    with open(encrypted_path, 'wb') as f: #Escribe en disco salt,nonce y encrypted
        f.write(salt + nonce + encrypted)
    
    return encrypted_path  #Devuelve la ruta del archivo cifrado

def decrypt_file(file_path, password):
    """Descifra archivo con AES-GCM."""
    if len(data := open(file_path, 'rb').read()) < 28:  # salt(16) + nonce(12), := abre el archivo en binario
        raise ValueError("Archivo inválido")  #Verifica que el archivo tenga al menos 28 bytes
    
    salt = data[:16]    #Extrae la sal(16 primeros bytes)
    nonce = data[16:28] #Extrae el nonce(siguientes 12 bytes))
    encrypted = data[28:] #Extrae el contenido cifrado(resto del archivo)
    
    key = derive_key(password, salt) #Deriva la clave usando la contraseña y la sal
    cipher = AESGCM(key)             #Instancia de un objeto AES-GCM con la key derivada
    decrypted = cipher.decrypt(nonce, encrypted, None)  #Descifra los datos
    
    #Interpreta los primeros 4 bytes del decrypted y lo interpreta como un entero big-endian
    meta_len = int.from_bytes(decrypted[:4], 'big')     
    metadata = json.loads(decrypted[4:4+meta_len].decode()) #Descodifica esos bytes(por defecto UTF-8) y parsea JSON)
    content = decrypted[4+meta_len:]        #Contenido original
    
    output_dir = os.path.dirname(file_path) #Directorio del archivo cifrado
    original_name = metadata['name']        #Obtiene el nombre original del archivo desde los metadatos
    decrypted_path = os.path.join(output_dir, f"decrypted_{original_name}") #Construye la ruta del archivo descifrado
    print(f"Intentando escribir en: {decrypted_path} con tamaño {len(content)} bytes")
    try:
        with open(decrypted_path, 'wb') as f: #Escribe el contenido descifrado en un nuevo archivo
            bytes_written = f.write(content)
        print(f"Escrito {bytes_written} bytes. Archivo existe: {os.path.exists(decrypted_path)}")
        print(f"Contenido descifrado: {content.decode('utf-8', errors='ignore')}")
        with open(decrypted_path, 'rb') as f: # Verifica el contenido escrito
            written_content = f.read()
        print(f"Contenido escrito: {written_content.decode('utf-8', errors='ignore')}")
        if bytes_written == 0:
            raise ValueError("No se escribió contenido")
    except IOError as e:
        raise ValueError(f"Error al escribir el archivo: {e}")
    
    return decrypted_path  #Devuelve la ruta del archivo descifrado

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