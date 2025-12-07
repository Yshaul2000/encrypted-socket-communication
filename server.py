"""Encrypted socket server implementation
   Author: Yinon Shaul 211693114
   Date:
"""

import socket
import protocol
import random


def create_server_rsp(cmd):
    """Based on the command, create a proper response"""
    return f"Server response {cmd}"


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    (client_socket, client_address) = server_socket.accept()
    print("Client connected")

    # Diffie Hellman
    # 1 - choose private key
    private_key_a = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    public_key = protocol.diffie_hellman_calc_public_key(private_key_a)
    # 3 - interact with client and calc shared secret

    # Receive the client's public key
    valid_msg,client_dh_public_key = protocol.get_msg(client_socket)
    if not valid_msg:
        print("Something went wrong with the length field")
        print("Closing\n")
        client_socket.close()
        server_socket.close()

    client_dh_public_key = int(client_dh_public_key)

    # Send the public key to the client
    message = protocol.create_msg(str(public_key))
    client_socket.send(message.encode())

    # Calculate shared secret
    shared_secret = protocol.diffie_hellman_calc_shared_secret(client_dh_public_key, private_key_a)
# ---------------------------------------------------------------------------------------------------------
    # RSA
    # Pick public key

    # My assumption is that the length of P and Q is 16 bits , and we need p * q > 2^16
    while True:
        P = random.randint(2 ** 8 + 1, 2 ** 9 - 1)
        Q = random.randint(2 ** 8 + 1, 2 ** 9 - 1)
        if protocol.is_prime(P) and protocol.is_prime(Q) and P != Q:
            break


    # The result of the signiture is in range 0 to P * Q , so calculate how many max bytes needed to
    # represent the signature
    SIGNITURE_IN_BYTES_SIZE = protocol.SIGNITURE_IN_BYTES_SIZE
    # The value of P * Q for the signature
    N = P * Q


    # Public key is prime , < T , T % Public key != 0
    server_rsa_public_key = 11
    T = (P - 1) * (Q - 1)
    while not (protocol.check_RSA_public_key(T, server_rsa_public_key)):
        #print("The public key is not work with the rules , please try again")
        server_rsa_public_key += 2


    # Calculate matching private key
    server_rsa_private_key = protocol.get_RSA_private_key(P,Q,server_rsa_public_key)

    # Exchange RSA public keys with client
    # Send public key to client
    msg_public_key = protocol.create_msg(str(server_rsa_public_key))
    client_socket.send(msg_public_key.encode())
    # Send N to the client
    msg_N = protocol.create_msg(str(N))
    client_socket.send(msg_N.encode())


    # Get the client public rsa key
    valid_msg,client_rsa_public_key = protocol.get_msg(client_socket)
    if not valid_msg:
        print("Something went wrong with the length field")
        print("Closing\n")
        client_socket.close()
        server_socket.close()

    client_rsa_public_key = int(client_rsa_public_key)

    # Get the client N
    valid_msg,client_N = protocol.get_msg(client_socket)
    if not valid_msg:
        print("Something went wrong with the length field")
        print("Closing\n")
        client_socket.close()
        server_socket.close()

    client_N = int(client_N)

    while True:
        # Receive client's message
        valid_msg, message = protocol.get_msg(client_socket)
        if not valid_msg:
            print("Something went wrong with the length field")
            break

        # Check if client's message is authentic
        # 1 - separate the message and the MAC
        # The data until the last SIGNITURE_IN_BYTES_SIZE bytes are the message
        client_message = message[:-SIGNITURE_IN_BYTES_SIZE]
        # The last SIGNITURE_IN_BYTES_SIZE bytes are the MAC
        client_mac = message[-SIGNITURE_IN_BYTES_SIZE:]


        # 2 - decrypt the message
        decrypted_client_message = protocol.symmetric_decryption(client_message, shared_secret)
        print(f"Client message after d: {decrypted_client_message}")

        # 3 - calc hash of message
        my_hash = protocol.calc_hash(decrypted_client_message)

        # 4 - use client's public RSA key to decrypt the MAC and get the hash
        # Convert the MAC from bytes to int
        client_mac = int.from_bytes(client_mac, byteorder='big')
        received_hash = pow(client_mac,client_rsa_public_key,client_N)

        # 5 - check if both calculations end up with the same result
        print(f"my_hash: {my_hash}, received_hash: {received_hash}")
        if my_hash == received_hash:
            print("The message is authentic")
        else:
            print("The message is not authentic")
            break

        # Check if the client wants to exit
        message = decrypted_client_message
        if message == "EXIT":
            break

        # Create response. The response would be the echo of the client's message
        response = create_server_rsp(decrypted_client_message)

        # Add MAC (signature)
        # 1 - calc hash of response
        server_hash = protocol.calc_hash(response)
        # 2 - calc the signature
        server_signature = protocol.calc_signature(server_hash, server_rsa_private_key, N)
        # -----------------------------------------------------------------------------------
        # Check if change the mac the client response will be not authentic
        #server_signature += 1
        # -----------------------------------------------------------------------------------
        # Convert the signature to bytes , byteorder='big' means the most significant byte is at the beginning
        bytes_server_signature = server_signature.to_bytes(SIGNITURE_IN_BYTES_SIZE, byteorder='big')

        # Encrypt
        # apply symmetric encryption to the server's message
        server_response_encrypt = protocol.symmetric_encryption(response,shared_secret)

        # Send to client
        # Combine encrypted user's message to MAC, send to client

        message = server_response_encrypt + bytes_server_signature
        msg = protocol.create_msg(message)
        # In encrypted message already in bytes , so no need to encode
        client_socket.send(msg)

    print("Closing\n")
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    main()
