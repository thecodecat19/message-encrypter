import tkinter as tk
from tkinter import messagebox
import base64

# Encryption algorithms
def caesar_cipher(text, shift, decrypt=False):
    if decrypt:
        shift = -shift
    result = ""
    for char in text:
        if char.isalpha():
            shift_base = ord('a') if char.islower() else ord('A')
            result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            result += char
    return result

def vigenere_cipher(text, key, decrypt=False):
    if decrypt:
        key = ''.join(chr((26 - (ord(char) - ord('A'))) % 26 + ord('A')) for char in key.upper())
    text = text.upper()
    key = generate_key(text, key.upper())
    encrypted_text = ""
    for i in range(len(text)):
        if text[i].isalpha():
            char_index = (ord(text[i]) + ord(key[i])) % 26 if not decrypt else (ord(text[i]) - ord(key[i]) + 26) % 26
            encrypted_text += chr(char_index + ord('A'))
        else:
            encrypted_text += text[i]
    return encrypted_text

def morse_code(text, decrypt=False):
    morse_dict = {
        'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..',
        '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----',
    }
    if decrypt:
        reversed_dict = {value: key for key, value in morse_dict.items()}
        decrypted_text = ''.join(reversed_dict[char] if char in reversed_dict else char for char in text.split())
        return decrypted_text
    else:
        encrypted_text = ' '.join(morse_dict[char.upper()] if char.upper() in morse_dict else char for char in text)
        return encrypted_text

def base64_encode(text, decrypt=False):
    if decrypt:
        decoded_text = base64.b64decode(text.encode()).decode()
        return decoded_text
    else:
        encoded_text = base64.b64encode(text.encode()).decode()
        return encoded_text

def generate_key(text=None, key=None):
    if key:
        return list(key)
    else:
        return 8  # sabit anahtar değeri

# Anonimlik yüzdeleri
anonimlik_yuzdeleri = {
    "Caesar Cipher": 70,
    "Vigenère Cipher": 85,
    "Morse Code": 50,
    "Base64": 60
}

# Create GUI
def on_encrypt():
    message = entry_message.get()
    cipher_type = cipher_var.get()
    key = generate_key()  # Anahtar değerini otomatik olarak oluştur

    if not message:
        messagebox.showerror("Error", "Message cannot be empty.")
        return

    if cipher_type == "Caesar Cipher":
        encrypted_message = caesar_cipher(message, key)
    elif cipher_type == "Vigenère Cipher":
        encrypted_message = vigenere_cipher(message, "SECRETKEY")
    elif cipher_type == "Morse Code":
        encrypted_message = morse_code(message)
    elif cipher_type == "Base64":
        encrypted_message = base64_encode(message)
    else:
        encrypted_message = "Invalid encryption method."

    entry_result.delete(0, tk.END)
    entry_result.insert(0, encrypted_message)

def on_decrypt():
    message = entry_message.get()
    cipher_type = cipher_var.get()
    key = generate_key()  # Anahtar değerini otomatik olarak oluştur

    if not message:
        messagebox.showerror("Error", "Message cannot be empty.")
        return

    if cipher_type == "Caesar Cipher":
        decrypted_message = caesar_cipher(message, key, decrypt=True)
    elif cipher_type == "Vigenère Cipher":
        decrypted_message = vigenere_cipher(message, "SECRETKEY", decrypt=True)
    elif cipher_type == "Morse Code":
        decrypted_message = morse_code(message, decrypt=True)
    elif cipher_type == "Base64":
        decrypted_message = base64_encode(message, decrypt=True)
    else:
        decrypted_message = "Invalid decryption method."

    entry_result.delete(0, tk.END)
    entry_result.insert(0, decrypted_message)

def update_anonimlik_yuzdesi(*args):
    cipher_type = cipher_var.get()
    anonimlik_yuzdesi = anonimlik_yuzdeleri.get(cipher_type, 0)
    label_anonimlik_yuzdesi.config(text=f"Anonimlik Yüzdesi: %{anonimlik_yuzdesi}")

def on_fullscreen(event=None):
    app.attributes("-fullscreen", True)

def on_escape(event=None):
    app.attributes("-fullscreen", False)

app = tk.Tk()
app.title("Message Encrypter Lang:EN")
app.configure(bg="#000000")  # Set background color to black

app.bind("<F11>", on_fullscreen)
app.bind("<Escape>", on_escape)

label_header = tk.Label(app, text="MESSAGE ENCRYPTER", font=("Helvetica", 24), bg="#000000", fg="#8B0000")
label_header.grid(row=0, column=0, columnspan=2, padx=10, pady=20)

label_alias = tk.Label(app, text="Welcome, anonymous!", bg="#000000", fg="#8B0000")
label_alias.grid(row=1, column=0, columnspan=2, padx=10, pady=10)

label_message = tk.Label(app, text="Message:", bg="#000000", fg="#8B0000")
label_message.grid(row=2, column=0, padx=10, pady=10)
entry_message = tk.Entry(app, width=50, fg="#8B0000", highlightbackground="#8B0000")
entry_message.grid(row=2, column=1, padx=10, pady=10)

label_cipher = tk.Label(app, text="Encryption Method:", bg="#000000", fg="#8B0000")
label_cipher.grid(row=3, column=0, padx=10, pady=10)
cipher_var = tk.StringVar(app)
cipher_var.set("Caesar Cipher")
cipher_var.trace("w", update_anonimlik_yuzdesi)
option_menu = tk.OptionMenu(app, cipher_var, "Caesar Cipher", "Vigenère Cipher", "Morse Code", "Base64")
option_menu.config(bg="#8B0000", fg="#FFFFFF")
option_menu.grid(row=3, column=1, padx=10, pady=10)

label_anonimlik_yuzdesi = tk.Label(app, text="Anonimlik Yüzdesi: %70", bg="#000000", fg="#8B0000")
label_anonimlik_yuzdesi.grid(row=4, column=0, columnspan=2, padx=10, pady=10)

button_encrypt = tk.Button(app, text="Encrypt", command=on_encrypt, bg="#8B0000", fg="#FFFFFF")
button_encrypt.grid(row=5, column=0, padx=10, pady=10)
button_decrypt = tk.Button(app, text="Decrypt", command=on_decrypt, bg="#8B0000", fg="#FFFFFF")
button_decrypt.grid(row=5, column=1, padx=10, pady=10)

label_result = tk.Label(app, text="Result:", bg="#000000", fg="#8B0000")
label_result.grid(row=6, column=0, padx=10, pady=10)
entry_result = tk.Entry(app, width=50, fg="#8B0000", highlightbackground="#8B0000")
entry_result.grid(row=6, column=1, padx=10, pady=10)

label_footer = tk.Label(app, text="by c7yb6rkedy", bg="#000000", fg="#8B0000", font=("Helvetica", 12))
label_footer.grid(row=7, column=0, columnspan=2, padx=10, pady=10)

app.mainloop()
