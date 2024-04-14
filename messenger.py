import os
import pickle
from cryptography.hazmat.primitives import hashes, serialization, hmac
import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import time


# Function to generate DH key pair.
def generate_DH():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


# Function to compute the shared secret using Diffie-Hellman key exchange.
def DH(private_key, other_party_pk):
    secret_key = private_key.exchange(ec.ECDH(), other_party_pk)
    return secret_key


# Function to derive keys from root key and DH output.
def KDF_RootKey(root_key, DH_output):
    derived_key = HKDF(
      algorithm=hashes.SHA256(),
      # Based on the signal implementation description of the HKDF output being divided into:
      # 32-byte encryption key, a 32-byte authentication key.
      length=64,
      # Recommended implementation is to use root_key as HKDF salt.
      salt=root_key,
      info=b'Root Chain').derive(DH_output)
    encryption_key = derived_key[:32]
    authentication_key = derived_key[32:64]
    return encryption_key, authentication_key


# Function to generate new chain key and message key using two different constants for each.
def KDF_ChainKey(chain_key):
    c_code = hmac.HMAC(chain_key, hashes.SHA256())
    c_code.update(b'Chain Key')
    chain_key = c_code.finalize()
    m_code = hmac.HMAC(chain_key, hashes.SHA256())
    m_code.update(b'Message Key')
    message_key = m_code.finalize()
    return chain_key, message_key


nonce = os.urandom(12)


class MessengerServer:

    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def signCert(self, cert):
        cert["not_valid_before"] = datetime.datetime.utcnow()
        cert["not_valid_after"] = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        cert["serial_number"] = int.from_bytes(os.urandom(16), byteorder="big")
        signature = self.server_signing_key.sign(pickle.dumps(cert), ec.ECDSA(hashes.SHA256()))
        return signature


class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.public_key = self.private_key.public_key()
        self.conns = {}
        self.certs = {}

    def generateCertificate(self):
        serialized_public_key = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        # Create certificate with client name and client serialized public key.
        # Validity dates and serial number are set to none as they would be set by server during signing.
        certificate = {
            "name": self.name,
            "public_key": serialized_public_key,
            "not_valid_before": None,
            "not_valid_after": None,
            "serial_number": None,
        }
        return certificate

    # Function to verify received certificate and add it to certs list of verified.
    def receiveCertificate(self, certificate, signature):
        self.server_signing_pk.verify(signature, pickle.dumps(certificate),
                                      ec.ECDSA(hashes.SHA256()))
        self.certs[certificate["name"]] = (certificate, signature)

    def sendMessage(self, name, message):
        message_key = b''
        # Check whether a connection with targeted recipient already exists.
        # If no, create a new connection and add it to connections list.
        if name not in self.conns:
            peer_public_key = self.certs[name][0]["public_key"]
            self.conns[name] = {
                "private_key": self.private_key,
                "public_key": self.public_key.public_bytes(
                  encoding=serialization.Encoding.PEM,
                  format=serialization.PublicFormat.SubjectPublicKeyInfo),
                "peer_public_key": peer_public_key,
                "root_key": bytes([0]) * 32,
                "send_chain_key": b'',
                "receive_chain_key": b'',
            }
        # If yes, load connection state.
        s_session_state = self.conns[name]

        # Check if the session is not initialized. If yes, do initialization steps.
        if len(s_session_state["send_chain_key"]) != 32:
            # Load and deserialize the recipient's public key (which we got from the certificate)
            peer_key = serialization.load_pem_public_key(s_session_state["peer_public_key"])
            # Perform the root and chain keys derivation.
            s_session_state["root_key"], s_session_state["send_chain_key"] = \
                KDF_RootKey(s_session_state["root_key"], DH(s_session_state["private_key"], peer_key))
        # Derive new chain key from current key and message key which would be used to encrypt the message.
        s_session_state["send_chain_key"], message_key = KDF_ChainKey(s_session_state["send_chain_key"])
        # Create header containing the sender's current ratchet public key.
        s_session_state["header"] = {
            "public_key": s_session_state["public_key"],
            "timestamp": time.time()
        }

        # Perform message encryption
        aesgcm = AESGCM(message_key)
        ciphertext = aesgcm.encrypt(nonce=nonce,
                                    data=message.encode('utf-8'),
                                    associated_data=pickle.dumps(s_session_state["header"]))

        self.conns[name] = s_session_state
        return self.conns[name]["header"], ciphertext

    def receiveMessage(self, name, header, ciphertext):
        # Check whether a connection with the sender already exists.
        # If no, create a new connection and add it to connections list.
        if name not in self.conns:
            peer_public_key = self.certs[name][0]["public_key"]
            self.conns[name] = {
                "private_key": self.private_key,
                "public_key":
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo),
                "peer_public_key": peer_public_key,
                # Root key is initialized by zero-filled byte as HKDF salt should be given that value.
                "root_key": bytes([0]) * 32,
                "send_chain_key": b'',
                "receive_chain_key": b'',
                }

        # If yes, load connection state.
        r_session_state = self.conns[name]

        # Check if the session is not initialized or if there's a mismatch in public keys in stored cert and header.
        if header["public_key"] != r_session_state["peer_public_key"] or \
                len(r_session_state["receive_chain_key"]) != 32:
            # Set sender (peer) public key to the one received in the header.
            r_session_state["peer_public_key"] = header["public_key"]
            # Load and deserialize sender public key which we got from the certificate.
            peer_pk = serialization.load_pem_public_key(r_session_state["peer_public_key"])
            # Perform the root and chain keys derivation for receiving the message.
            r_session_state["root_key"], r_session_state["receive_chain_key"] = \
                KDF_RootKey(r_session_state["root_key"], DH(r_session_state["private_key"], peer_pk))
            # Generate new private and public keys.
            new_private_key, new_public_key = generate_DH()
            # Perform new root and chain keys derivation for sending messages.
            r_session_state["root_key"], r_session_state["send_chain_key"] = KDF_RootKey(
                  r_session_state["root_key"], DH(new_private_key, peer_pk))
            # Update the session's client public key and serialize it.
            r_session_state["public_key"] = new_public_key.public_bytes(
              encoding=serialization.Encoding.PEM,
              format=serialization.PublicFormat.SubjectPublicKeyInfo)
            # Update the session's client private key and serialize it.
            r_session_state["private_key"] = new_private_key
        # Derive new the chain key for next time and the message key for decrypting the message.
        r_session_state["receive_chain_key"], message_key = KDF_ChainKey(r_session_state["receive_chain_key"])

        # Try to perform decryption. If an issue with decryption occurs, return None.
        try:
            aesgcm = AESGCM(message_key)
            plaintext = aesgcm.decrypt(nonce=nonce, data=ciphertext,
                                              associated_data=pickle.dumps(header))
            plaintext = plaintext.decode('utf-8')
        except Exception:
            return None

        self.conns[name] = r_session_state
        return plaintext
