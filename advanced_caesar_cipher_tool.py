from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
import string
import logging
from tkinter import Tk, Label, Entry, Button, StringVar, Radiobutton, messagebox, Frame, Toplevel, NORMAL, DISABLED

class CaesarCipher:
    """ Represents the Caesar Cipher encryption and decryption. """
    def __init__(self, shift: int):
        self.shift = shift % 26  # Normalize shift value
        self.uppercase = string.ascii_uppercase
        self.lowercase = string.ascii_lowercase

    def encrypt(self, text: str) -> str:
        return self._transform(text, self.shift)

    def decrypt(self, text: str) -> str:
        return self._transform(text, -self.shift)

    def _transform(self, text: str, shift: int) -> str:
        result = []
        for char in text:
            if char.isupper():
                idx = (self.uppercase.index(char) + shift) % 26
                result.append(self.uppercase[idx])
            elif char.islower():
                idx = (self.lowercase.index(char) + shift) % 26
                result.append(self.lowercase[idx])
            else:
                result.append(char)
        return ''.join(result)

class HybridEncryption:
    """ Combines Caesar Cipher with AES encryption for a hybrid encryption system. """
    key = Fernet.generate_key()  
    aes_cipher = Fernet(key)  

    def __init__(self, shift: int):
        self.caesar_cipher = CaesarCipher(shift)

    def encrypt(self, text: str) -> str:
        caesar_encrypted = self.caesar_cipher.encrypt(text)
        aes_encrypted = self.aes_cipher.encrypt(caesar_encrypted.encode()).decode()
        return aes_encrypted

    def decrypt(self, text: str) -> str:
        try:
            aes_decrypted = self.aes_cipher.decrypt(text.encode()).decode()
            caesar_decrypted = self.caesar_cipher.decrypt(aes_decrypted)
            return caesar_decrypted
        except Exception as e:
            logging.error(f"Decryption failed: {str(e)}")
            raise


app = Flask(__name__)


logging.basicConfig(filename='encryption_service.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    try:
        data = request.json
        text = data['text']
        shift = int(data['shift'])
        hybrid_cipher = HybridEncryption(shift)
        encrypted_text = hybrid_cipher.encrypt(text)
        logging.info(f"Message encrypted: {text} -> {encrypted_text}")
        return jsonify({"encrypted": encrypted_text})
    except Exception as e:
        logging.error(f"Encryption error: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        text = data['text']
        shift = int(data['shift'])
        hybrid_cipher = HybridEncryption(shift)
        decrypted_text = hybrid_cipher.decrypt(text)
        logging.info(f"Message decrypted: {text} -> {decrypted_text}")
        return jsonify({"decrypted": decrypted_text})
    except Exception as e:
        logging.error(f"Decryption error: {str(e)}")
        return jsonify({"error": str(e)}), 400

def run_server():
    """ Runs the Flask server. """
    app.run(debug=True)

# GUI 
def validate_shift(shift: str) -> int:
    """ Validates the shift input. """
    try:
        shift = int(shift)
        if shift < 0:
            raise ValueError("Shift must be a non-negative integer.")
        return shift
    except ValueError as e:
        messagebox.showerror("Error", f"Invalid shift value! {e}")
        return None

def process_text():
    """ Processes the text for encryption or decryption based on the user's choice. """
    text = text_var.get()
    shift = validate_shift(shift_var.get())
    if shift is None:
        return
    
    cipher = HybridEncryption(shift)
    try:
        if mode_var.get() == "encrypt":
            result = cipher.encrypt(text)
        else:
            result = cipher.decrypt(text)
        result_var.set(result)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

def copy_to_clipboard(content: str):
    """ Copies the given content to the clipboard. """
    app.clipboard_clear()
    app.clipboard_append(content)
    app.update()  # clipboard 
    messagebox.showinfo("Copied", "Content copied to clipboard!")

def show_help():
    """ Displays a help dialog. """
    help_window = Toplevel(app)
    help_window.title("Help")
    help_window.geometry("300x200")
    help_window.configure(bg='#f0f0f0')
    
    help_text = (
        "Advanced Hybrid Encryption Tool\n\n"
        "1. Enter the text you want to encrypt or decrypt.\n"
        "2. Enter the shift value for the Caesar Cipher.\n"
        "3. Choose the mode: Encrypt or Decrypt.\n"
        "4. Click 'Process' to perform the action.\n"
        "5. Click 'Copy Result' to copy the output to clipboard.\n"
    )
    
    Label(help_window, text=help_text, padx=10, pady=10, bg='#f0f0f0').pack()
    Button(help_window, text="Close", command=help_window.destroy, bg='#4CAF50', fg='white').pack(pady=10)


app = Tk()
app.title("Advanced Caesar Cipher Tool")
app.geometry("800x500")
app.configure(bg='#e0e0e0')
description_label = Label(app, text="Welcome to the Advanced Caesar Cipher Tool!\n"
                                    "This tool combines Caesar Cipher with AES encryption for enhanced security. \n"
                                    "You can encrypt and decrypt text using a hybrid approach.",
                          font=("Arial", 14), bg='#e0e0e0', fg='#333333', pady=5)
description_label.pack()

main_frame = Frame(app, padx=20, pady=20, bg='#e0e0e0')
main_frame.pack(expand=True, fill='both')

text_var = StringVar()
shift_var = StringVar()
result_var = StringVar()
mode_var = StringVar(value="encrypt")


Label(main_frame, text="Enter Text:", font=("Arial", 12), bg='#e0e0e0').grid(row=0, column=0, sticky='e', padx=10, pady=10)
text_entry = Entry(main_frame, textvariable=text_var, font=("Arial", 12), width=60, bg='#ffffff', fg='#000000')
text_entry.grid(row=0, column=1, padx=10, pady=10)


Label(main_frame, text="Shift Value:", font=("Arial", 12), bg='#e0e0e0').grid(row=1, column=0, sticky='e', padx=10, pady=10)
shift_entry = Entry(main_frame, textvariable=shift_var, font=("Arial", 12), width=30, bg='#ffffff', fg='#000000')
shift_entry.grid(row=1, column=1, padx=10, pady=10)


Radiobutton(main_frame, text="Encrypt", variable=mode_var, value="encrypt", font=("Arial", 12), bg='#e0e0e0', fg='#0000ff').grid(row=2, column=0, padx=10, pady=10, sticky='e')
Radiobutton(main_frame, text="Decrypt", variable=mode_var, value="decrypt", font=("Arial", 12), bg='#e0e0e0', fg='#ff0000').grid(row=2, column=1, padx=10, pady=10, sticky='w')


Button(main_frame, text="Process", command=process_text, font=("Arial", 12), width=20, bg='#2196F3', fg='white').grid(row=3, columnspan=2, pady=20)


Label(main_frame, text="Result:", font=("Arial", 12), bg='#e0e0e0').grid(row=4, column=0, sticky='e', padx=10, pady=10)
result_entry = Entry(main_frame, textvariable=result_var, font=("Arial", 12), width=60, state=DISABLED, bg='#ffffff', fg='#000000')
result_entry.grid(row=4, column=1, padx=10, pady=10)


Button(main_frame, text="Copy Result", command=lambda: copy_to_clipboard(result_var.get()), font=("Arial", 12), bg='#4CAF50', fg='white').grid(row=5, columnspan=2, pady=10)

# Help 
Button(main_frame, text="Help", command=show_help, font=("Arial", 12), bg='#FFC107', fg='black').grid(row=6, columnspan=2, pady=10)

# Run 
app.mainloop()

