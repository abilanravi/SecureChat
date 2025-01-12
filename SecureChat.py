from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import bcrypt
from datetime import datetime
import os
import pickle
import json

class User:
    def __init__(self, username, password):
        self.username = username
        self.password_hash = self._hash_password(password)
        self.public_key, self.private_key = self.generate_keys()

    def _hash_password(self, password):
        # Hash the password using bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    def verify_password(self, password):
        # Verify the provided password against the stored hash
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())

    def generate_keys(self):
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return public_key, private_key

    def to_dict(self):
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "public_key": self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }

    @staticmethod
    def from_dict(data):
        user = User(data["username"], "")
        user.password_hash = data["password_hash"]
        user.public_key = serialization.load_pem_public_key(
            data["public_key"].encode(), backend=default_backend()
        )
        return user

class Message:
    def __init__(self, sender, recipient, encrypted_content):
        self.sender = sender
        self.recipient = recipient
        self.encrypted_content = encrypted_content
        self.timestamp = datetime.now()

    def __repr__(self):
        return f"Message from {self.sender} to {self.recipient} at {self.timestamp}"

    def to_dict(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "encrypted_content": self.encrypted_content.hex(),
            "timestamp": self.timestamp.isoformat()
        }

    @staticmethod
    def from_dict(data):
        message = Message(
            sender=data["sender"],
            recipient=data["recipient"],
            encrypted_content=bytes.fromhex(data["encrypted_content"])
        )
        message.timestamp = datetime.fromisoformat(data["timestamp"])
        return message

def encrypt_message(content, recipient_public_key):
    return recipient_public_key.encrypt(
        content.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_message(encrypted_content, private_key):
    return private_key.decrypt(
        encrypted_content,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    ).decode()

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password, password_hash):
    return bcrypt.checkpw(password.encode(), password_hash.encode())

def save_data(users, messages):
    users_data = [user.to_dict() for user in users]
    messages_data = [msg.to_dict() for msg in messages]

    with open('users.json', 'w') as users_file:
        json.dump(users_data, users_file, indent=4)

    with open('messages.json', 'w') as messages_file:
        json.dump(messages_data, messages_file, indent=4)

def load_data():
    if os.path.exists('users.json') and os.path.exists('messages.json'):
        with open('users.json', 'r') as users_file:
            users_data = json.load(users_file)
            users = [User.from_dict(user) for user in users_data]

        with open('messages.json', 'r') as messages_file:
            messages_data = json.load(messages_file)
            messages = [Message.from_dict(msg) for msg in messages_data]

        return users, messages

    return [], []

def initialize_system():
    users, messages = load_data()
    print("Welcome to SecureChat!")
    return users, messages

def main_menu(users, messages):
    while True:
        print("\nMain Menu:")
        print("1. Register")
        print("2. Login")
        print("3. Exit")

        try:
            user_choice = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 3.")
            continue

        if user_choice == 1:
            register_user(users)
        elif user_choice == 2:
            user = login_user(users)
            if user:
                chat_menu(user, users, messages)
        elif user_choice == 3:
            save_data(users, messages)
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

def register_user(users):
    username = input("Enter a username: ")
    password = input("Enter a password: ")

    # Check if username already exists
    if any(user.username == username for user in users):
        print("Username already exists. Please try again.")
        return

    # Create a new user and add to the list
    new_user = User(username, password)
    users.append(new_user)
    print("Registration successful!")

def login_user(users):
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Find the user by username
    user = next((user for user in users if user.username == username), None)

    if user and user.verify_password(password):
        print("Login successful!")
        return user
    else:
        print("Invalid credentials. Please try again.")
        return None

def chat_menu(current_user, users, messages):
    while True:
        print("\nChat Menu:")
        print("1. Send Message")
        print("2. View Messages")
        print("3. Logout")

        try:
            user_choice = int(input("Enter your choice: "))
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 3.")
            continue

        if user_choice == 1:
            send_message(current_user, users, messages)
        elif user_choice == 2:
            view_messages(current_user, messages)
        elif user_choice == 3:
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

def send_message(current_user, users, messages):
    recipient_username = input("Enter the recipient's username: ")
    recipient = next((user for user in users if user.username == recipient_username), None)

    if recipient:
        message_content = input("Enter your message: ")
        encrypted_content = encrypt_message(message_content, recipient.public_key)
        new_message = Message(sender=current_user.username, recipient=recipient.username, encrypted_content=encrypted_content)
        messages.append(new_message)
        print("Message sent!")
    else:
        print("Recipient not found.")

def view_messages(current_user, messages):
    user_messages = [msg for msg in messages if msg.recipient == current_user.username]

    if not user_messages:
        print("No messages found.")
        return

    for msg in user_messages:
        try:
            decrypted_content = decrypt_message(msg.encrypted_content, current_user.private_key)
            print(f"From {msg.sender} at {msg.timestamp}: {decrypted_content}")
        except Exception as e:
            print(f"Failed to decrypt a message from {msg.sender}: {e}")

def main():
    users, messages = load_data()
    initialize_system()
    main_menu(users, messages)

if __name__ == "__main__":
    main()
