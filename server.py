#!/usr/bin/env python3
# Owner: Jelle Groot
# Studiejaar: 2023-2024
# Datum: 02/02/2024
# Versie: 1.0

import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import padding
from cryptography import x509
import secrets
    
class Connection:
    def __init__(self, host, port, name):
        self.host = host
        self.port = port
        self.name = name
        self.server_socket = None
        self.conn = None
        self.shared_key = None
        self.iv = None

    def connect(self):
        self.server_socket = socket.socket()
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(2)
        self.conn, self.address = self.server_socket.accept()
        print("Connection from: " + str(self.address))
        
        self.conn.send(b"ServerHello") # Simulate TLS handshake
        print("Sent: ServerHello")
        response = self.conn.recv(1024)
        if response == b"ClientHello":
            print("Received: ClientHello")
        
        self.shared_key = Diffie_Hellman('server/private-key.pem', 'client/cert.pem').Shared_key()
        
        self.conn.send(b"Finished")
        print("Sent: Finished")
        print("TLS 1.2 handshake complete")


    def receive_message(self):
        rcv_msg = self.conn.recv(1024)
        # Split the received message into IV and encrypted data
        if len(rcv_msg) == 32:  # Assuming 16 bytes IV and 16 bytes ciphertext
            iv = rcv_msg[:16]
            encrypted_data = rcv_msg[16:]
        else:
            print("Malformed message received.")
            return None

        cipher = Cipher(algorithms.AES(self.shared_key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Perform unpadding if needed
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        recv_data = unpadder.update(decrypted_data) + unpadder.finalize()

        if recv_data:
            return recv_data.decode('utf-8')
        else:
            return None

    def send_message(self, message):
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(self.shared_key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()

        if type(message) == bytes:
            padded_data = padder.update(message) + padder.finalize()
        else:
            padded_data = padder.update(message.encode('utf-8')) + padder.finalize()

        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        # Include the IV in the message
        send_msg = iv + ciphertext

        self.conn.send(send_msg)

class Diffie_Hellman():
    def __init__(self, private_key_path, cert_file_path):
        self.private_key = private_key_path
        self.certificate = cert_file_path
        

    def open_privatekey_and_cert(self):
        # Open the private key PEM file
        with open(self.private_key, 'rb') as keyfile:
            keyfile_data = keyfile.read()

        # Open the certificate PEM file
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

def server():
    host = socket.gethostname()
    port = 8443
    name = "Alice"
    conn = Connection(host, port, name)
    conn.connect()

    while True:
        message = conn.receive_message()
        # Print received message
        print("Bob:" + str(message))
        # Send message
        message = input("Alice: ")
        conn.send_message(message=message)
    
    #? Terminate the connection
    conn.closeConnection()


if __name__ == '__main__':
    server()
