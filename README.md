# SecureChat

**Author:** Abilan Ravindran

## Project Motivation
After completing an intro to cryptography and its applications class, I wanted to challenge myself by building a practical application that utilized the concepts I learned. SecureChat is the result of this effort, designed to test and solidify my understanding of encryption techniques and secure data management.

## Project Description
SecureChat is a command-line chat application that ensures secure communication between users through end-to-end encryption. It leverages RSA for key exchange and AES-like encryption for messages, ensuring that messages remain private and tamper-proof during transmission.

### Features:
1. **User Registration and Login:**
   - Users can register with a unique username and password.
   - Passwords are securely hashed using bcrypt before storage.

2. **End-to-End Encrypted Messaging:**
   - Messages are encrypted using the recipient's RSA public key.
   - Only the recipient can decrypt messages using their private key.

3. **Message Storage:**
   - Sent messages are stored in a JSON file (`messages.json`) for future retrieval.

4. **Data Persistence:**
   - User details, excluding private keys, are securely stored in a JSON file (`users.json`).
   - Messages and user data persist between application sessions.

## How It Works
1. Users register by providing a username and password. A unique RSA key pair is generated for each user.
2. Registered users can log in to send and view messages.
3. Messages sent are encrypted with the recipient's public key and stored in `messages.json`.
4. Users can view their messages, which are decrypted in real-time using their private key.

### JSON Files:
- `users.json`: Stores user details such as usernames, password hashes, and public keys.
- `messages.json`: Stores encrypted messages along with metadata (sender, recipient, timestamp).

## Getting Started
### Prerequisites:
- Python 3.7 or later
- Required libraries:
  ```
  pip install cryptography bcrypt
  ```

### Running the Application:
1. Save the script as `securechat.py`.
2. Run the application:
   ```
   python securechat.py
   ```

## Future Improvements
- Implement a graphical user interface (GUI) for better usability.
- Add support for group messaging.
- Enhance security by introducing additional authentication mechanisms.

---
Thank you for exploring SecureChat! Feel free to reach out for feedback or questions.

