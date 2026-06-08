import base64
import hashlib
import hmac
import os
import tkinter as tk
from tkinter import messagebox, ttk


def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a 32-byte encryption key from a password using PBKDF2."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000, 32)


def process_encode():
    message = message_entry.get("1.0", tk.END).strip()
    password = password_entry.get().strip()

    if not message or not password:
        messagebox.showwarning("Error", "Please enter both a message and a password!")
        return

    # 1. Generate random salt and initialization vector (IV)
    salt = os.urandom(16)
    iv = os.urandom(16)

    # 2. Derive key and encrypt via custom stream cipher
    key = derive_key(password, salt)
    message_bytes = message.encode()

    keystream = b""
    counter = 0
    while len(keystream) < len(message_bytes):
        keystream += hashlib.sha256(key + iv + counter.to_bytes(4, "big")).digest()
        counter += 1

    encrypted_bytes = bytes(b ^ k for b, k in zip(message_bytes, keystream))

    # 3. Create a verification tag (HMAC)
    password_tag = hmac.new(key, b"verify_password", hashlib.sha256).digest()

    # 4. Pack into a base64 string
    final_payload = salt + iv + password_tag + encrypted_bytes
    encoded_block = base64.b64encode(final_payload).decode("utf-8")

    # Display results and auto-copy to clipboard
    output_entry.delete("1.0", tk.END)
    output_entry.insert("1.0", encoded_block)

    root.clipboard_clear()
    root.clipboard_append(encoded_block)
    messagebox.showinfo(
        "Success", "Text encoded and copied to clipboard successfully!"
    )


# --- GUI Setup ---
root = tk.Tk()
root.title("Secure Text Encoder")
root.geometry("450x450")

style = ttk.Style()
style.theme_use("clam")

# Layout
ttk.Label(root, text="Secret Message:").pack(anchor="w", padx=10, pady=(10, 2))
message_entry = tk.Text(root, height=5, wrap="word")
message_entry.pack(fill="x", padx=10)

ttk.Label(root, text="Password / Key:").pack(anchor="w", padx=10, pady=(10, 2))
password_entry = ttk.Entry(root, show="*")
password_entry.pack(fill="x", padx=10)

ttk.Button(root, text="🔒 Encode Message", command=process_encode).pack(
    pady=15, padx=10, fill="x"
)

ttk.Label(root, text="Output (Big Text Block):").pack(
    anchor="w", padx=10, pady=(10, 2)
)
output_entry = tk.Text(root, height=8, wrap="word")
output_entry.pack(fill="x", padx=10)

root.mainloop()
