#!/usr/bin/env python3
# Owner: Jelle Groot
# Studiejaar: 2023-2024
# Datum: 02/02/2024
# Versie: 1.0

import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography import x509
import secrets


class ConnectionClient:
    def __init__(self, host, port, name, shared_key):
        self.host = host
        self.port = port
        self.name = name
        self.shared_key = shared_key
  

    def connect(self):
        # Create a socket object
        self.client_socket = socket.socket()
        # Connect to the server
        self.client_socket.connect((self.host, self.port))
        # Perform the TLS handshake
        response = self.client_socket.recv(1024)
        if response == b"ServerHello":
            print("Received: ServerHello")
            self.client_socket.send(b"ClientHello")
            print("Sent: ClientHello")
        # Create the shared key
        self.shared_key = Diffie_Hellman('client/private-key.pem', 'server/cert.pem').Shared_key()
        
        response = self.client_socket.recv(1024)
        if response == b"Finished":
            print("Received: Finished")
            print("TLS 1.2 handshake completed")

    def send_message(self, message):
        #  Set the connection client to the client socket
        conn_client = self.client_socket
        # Create a random IV
        iv = secrets.token_bytes(16)
        # Create the AES cipher
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CFB(iv), backend=default_backend())
        # Create the encryptor
        encryptor = cipher.encryptor()
        # Perform padding
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        # Encrypt the message
        if type(message) == bytes:
            padded_data = padder.update(message) + padder.finalize()
        else:
            padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Include the IV in the message
        send_msg = iv + ciphertext

        # Send the message
        conn_client.send(send_msg)

    def receive_message(self):
        # Receive the message
        rcv_msg = self.client_socket.recv(1024)

        # Split the received message into IV and encrypted data
        if len(rcv_msg) == 32:  
            iv = rcv_msg[:16]
            encrypted_data = rcv_msg[16:]
        else:
            print("Unsupported message received.")
            return None
        # Create the AES cipher
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CFB(iv), backend=default_backend())
        # Create the decryptor
        decryptor = cipher.decryptor()
        # Decrypt the message
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Perform unpadding if needed
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        recv_data = unpadder.update(decrypted_data) + unpadder.finalize()

        # Return the received message
        if recv_data:
            return recv_data.decode('utf-8')   
        else:
            return None
        
class Diffie_Hellman():
    def __init__(self, private_key_path, cert_file_path):
        self.private_key = private_key_path
        self.certificate = cert_file_path
        
    def open_privatekey_and_cert(self):
        # Open the private key PEM file
        with open(self.private_key, 'rb') as keyfile:
            keyfile_data = keyfile.read()

        # Open the certificate PEM filek
        with open(self.certificate, 'rb') as certfile:
            certfile_data = certfile.read()

        # Load the private key from the PEM file format
        key = serialization.load_pem_private_key(keyfile_data, password=None, backend=default_backend())
        
        self.priv_key_loaded = key

        # Load the certificate from the PEM file format 
        cert = x509.load_pem_x509_certificate(certfile_data, default_backend())

        # Extract the public key from the certificate
        self.public_key_conn_client = cert.public_key()

        # Return the public key so that it can be used to create the shared key
        return self.public_key_conn_client, self.priv_key_loaded
    

    def Shared_key(self):
        # Load the private key and the certificate
        self.open_privatekey_and_cert()
        # Create the shared key
        shared_key = self.priv_key_loaded.exchange(ec.ECDH(), self.public_key_conn_client)

        # Print the public key received and the shared key created for the handshake
        print("Public Key received")
        print("Shared Key created")
    
        return shared_key

def client():
    host = socket.gethostname()
    port = 8443
    name = "Bob"
    shared_key = None
    conn_client = ConnectionClient(host, port, name, shared_key)
    conn_client.connect()

    conn_client.message = input(f"Bob: ")
    conn_client.send_message(message=conn_client.message)
    
    while True:
        received_message = conn_client.receive_message()
        print("Alice:" + str(received_message))
        #? Send message
        conn_client.message = input(f"Bob: ")
        conn_client.send_message(message=conn_client.message)
            

if __name__ == '__main__':
    client()
