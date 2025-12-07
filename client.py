"""Encrypted socket client implementation
   Author: Yinon Shaul 211693114
   Date:
"""

import socket
import protocol
import random


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    # Diffie Hellman
    # 1 - choose private key
    private_key_b = protocol.diffie_hellman_choose_private_key()
    # 2 - calc public key
    public_key = protocol.diffie_hellman_calc_public_key(private_key_b)
    # 3 - interact with server and calc shared secret

    # Send the public key to the server
    message = protocol.create_msg(str(public_key))
    my_socket.send(message.encode())
    # Receive the server's public key
    valid_msg,server_dh_public_key = protocol.get_msg(my_socket)
    if not valid_msg:
        print("Something went wrong with the length field")
        print("Closing\n")
        my_socket.close()

    server_dh_public_key = int(server_dh_public_key)
    # Calculate shared secret
    shared_secret = protocol.diffie_hellman_calc_shared_secret(server_dh_public_key, private_key_b)
# -----------------------------------------------------------------------------------------------------------
    # RSA
    # Pick public key

    # My assumption is that the length of P and Q is 9 bits , and we need p * q > 2^16
    # P * Q is max
    while True:
        P = random.randint(2**8 + 1 ,2**9 -1)
        Q = random.randint(2**8 + 1 ,2**9 -1)
        if protocol.is_prime(P) and protocol.is_prime(Q) and P != Q:
            break

    # The result of the signiture is in range 0 to P * Q , so calculate how many max bytes needed to
    # represent the signature
    SIGNITURE_IN_BYTES_SIZE = protocol.SIGNITURE_IN_BYTES_SIZE
    # The value of P * Q for the signature
    N = P * Q


    # Public key is prime , < T , T % Public key != 0
    client_rsa_public_key = 17
    T = (P - 1) * (Q - 1)

    while not (protocol.check_RSA_public_key(T,client_rsa_public_key)):
        client_rsa_public_key += 2

    # Calculate matching private key
    client_rsa_private_key = protocol.get_RSA_private_key(P,Q,client_rsa_public_key)

    # Exchange RSA public keys with server
    # Send the public key to server
    msg_public_key = protocol.create_msg(str(client_rsa_public_key))
    my_socket.send(msg_public_key.encode())
    # Send the P * Q  = N to the server
    msg_N = protocol.create_msg(str(N))
    my_socket.send(msg_N.encode())

    # Get server public rsa key
    valid_msg,server_rsa_public_key = protocol.get_msg(my_socket)
    if not valid_msg:
        print("Something went wrong with the length field or server closed the connection")
        print("Closing\n")
        my_socket.close()
    server_rsa_public_key = int(server_rsa_public_key)

    # Get server N
    valid_msg,server_N = protocol.get_msg(my_socket)
    if not valid_msg:
        print("Something went wrong with the length field or server closed the connection")
        print("Closing\n")
        my_socket.close()
    server_N = int(server_N)

    while True:
        user_input = input("Enter command\n")
        # Add MAC (signature)
        # 1 - calc hash of user input
        client_hash = protocol.calc_hash(user_input)
        # 2 - calc the signature
        client_signature = protocol.calc_signature(client_hash, client_rsa_private_key, N)
        # -----------------------------------------------------------------------------------
        # Check if change the mac the server response will be not authentic
        # client_signature += 1
        # -----------------------------------------------------------------------------------

        # Convert the signature to bytes , byteorder='big' means the most significant byte is at the beginning
        bytes_client_signature = client_signature.to_bytes(SIGNITURE_IN_BYTES_SIZE, byteorder='big')

        # Encrypt
        # apply symmetric encryption to the user's input
        print(f"User input: {user_input}")
        encrypted_user_message = protocol.symmetric_encryption(user_input, shared_secret)

        # Send to server

        user_msg = encrypted_user_message + bytes_client_signature
        msg = protocol.create_msg(user_msg)
        # In encrypted message already in bytes , so no need to encode
        my_socket.send(msg)


        # If the user wants to exit send EXIT to the server , and don't wait for response
        if user_input == 'EXIT':
            break

        # Receive server's message
        valid_msg, message = protocol.get_msg(my_socket)
        if not valid_msg:
            print("Something went wrong with the length field or server closed the connection")
            break
        # Check if server's message is authentic
        # 1 - separate the message and the MAC
        # The data until the last SIGNITURE_IN_BYTES_SIZE bytes are the message
        server_res = message[:-SIGNITURE_IN_BYTES_SIZE]
        # The last SIGNITURE_IN_BYTES_SIZE bytes are the MAC
        server_mac = message[-SIGNITURE_IN_BYTES_SIZE:]


        # 2 - decrypt the message
        # Because the encrypted message is by symmetric encryption
        decrypted_server_res = protocol.symmetric_decryption(server_res, shared_secret)
        # 3 - calc hash of message
        my_hash = protocol.calc_hash(decrypted_server_res)

        # 4 - use server's public RSA key to decrypt the MAC and get the hash
        # Convert the MAC from bytes to int
        server_mac = int.from_bytes(server_mac, byteorder='big')
        received_hash = pow(server_mac,server_rsa_public_key,server_N)

        # 5 - check if both calculations end up with the same result
        print(f"my_hash: {my_hash}, received_hash: {received_hash}")
        if my_hash == received_hash:
            print("The message is authentic")
        else:
            # Throw the massage because the message is not authentic
            print("The message is not authentic")
            break

        # Print server's message
        print(f"Server response: {decrypted_server_res}")

    print("Closing\n")
    my_socket.close()

if __name__ == "__main__":
    main()
