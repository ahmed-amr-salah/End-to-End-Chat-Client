#  Project Overview

This project entails the development of a secure private messaging application's backend using Python. Leveraging the renowned Double Ratchet Algorithm, which is extensively used in popular end-to-end encrypted messaging platforms like WhatsApp and Signal, we ensure robust security and confidentiality for user communications.

# Key Components:

1. **Initialization**: The server and clients are initialized with asymmetric keys using the Elliptic Curve Cryptography (ECC) module from the Python cryptography library.

2. **Certificate Management**: The server generates and signs certificates for each client, ensuring secure communication channels.

3. **Conversation Handling**: Clients exchange messages securely using the Double Ratchet Algorithm. Each message is encrypted, ensuring only the intended recipient can decrypt and read it.

4. **Error Handling**: The system is designed to handle various error scenarios, including incorrect certificate issuance and malformed messages, ensuring the integrity and security of the communication process.

# Testing:

The code includes comprehensive testing scenarios to validate the correct implementation of encryption, decryption, and certificate verification functionalities. This ensures the reliability and robustness of the messaging application under different conditions.

# Usage:

To utilize this backend for your private messaging application:

1. Clone the repository.
2. Ensure you have Python 3 installed along with the required dependencies, including the cryptography library.
3. Execute the main script, which initializes the server and clients, generates certificates, and simulates a conversation between clients.
4. Review the output for successful message exchange and error handling.

# Tech Stack:

![Python](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=python&logoColor=white)
