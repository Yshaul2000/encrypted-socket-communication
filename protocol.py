"""Encrypted sockets implementation
   Author: Yinon Shaul 211693114
   Date:
"""
import math
import random
import base64

LENGTH_FIELD_SIZE = 2
PORT = 8820

DIFFIE_HELLMAN_P = 65521
DIFFIE_HELLMAN_G = 3

# ---------------------------------------

# Because use in T more than one time save T for two sides
# RSA_T = (RSA_P - 1) * (RSA_Q - 1)

# The result of the signiture is in range 0 to P * Q , so calculate how many max bytes needed to
# represent the signature , we now that the p * q is max in range of 18 bits (9 bits * 9 bits)
'''
SIGNITURE_IN_BITS_SIZE = (RSA_P * RSA_Q).bit_length()
# Adding 7 ensures we round up to the nearest byte , 18 bits + 7 // 8 -> 3 bytes
'''
SIGNITURE_IN_BYTES_SIZE = 3

# ----------------------------------------------------------

# Create a random Look-Up Table in numbers between 0 and 255
lookup_table = [2, 184, 176, 8, 165, 22, 63, 215, 45, 89, 188, 36, 198, 82, 118, 0, 81, 150, 42, 224, 175, 152, 41,
                131, 59, 24, 247, 177, 179, 173, 138, 201, 1, 212, 65, 86, 30, 4, 95, 125, 25, 164, 39, 57, 167, 227,
                98, 211, 61, 248, 202, 120, 147, 193, 171, 183, 60, 196, 111, 185, 53, 213, 178, 223, 28, 207, 27, 149,
                174, 186, 162, 16, 170, 230, 236, 76, 58, 23, 96, 26, 163, 77, 135, 102, 255, 203, 200, 122, 112, 151,
                159, 155, 216, 115, 238, 44, 143, 146, 74, 33, 12, 103, 166, 208, 50, 11, 64, 48, 141, 113, 108, 62,
                191, 87, 233, 209, 51, 54, 241, 190, 126, 240, 168, 37, 204, 254, 84, 94, 32, 71, 237, 154, 160, 153,
                140, 18, 142, 231, 106, 105, 195, 205, 68, 169, 137, 99, 67, 123, 92, 145, 83, 161, 187, 157, 72, 56,
                194, 3, 246, 6, 31, 128, 46, 7, 55, 129, 119, 66, 243, 17, 49, 116, 197, 93, 180, 229, 69, 132, 222,
                242, 210, 47, 75, 35, 117, 251, 29, 199, 218, 127, 52, 234, 97, 182, 34, 219, 221, 133, 250, 21, 73,
                232, 20, 253, 214, 217, 206, 244, 100, 172, 14, 156, 38, 70, 104, 101, 144, 88, 252, 226, 121, 5, 158,
                245, 239, 85, 13, 90, 79, 192, 124, 91, 9, 78, 43, 80, 139, 220, 107, 40, 130, 228, 235, 148, 110, 15,
                10, 109, 19, 181, 134, 136, 225, 249, 114, 189]

# -------------------In the encryption the input string , and in the decryption the input is bytes ------------
def symmetric_encryption(input_data, key):
    """Return the encrypted / decrypted data
    The key is 16 bits. If the length of the input data is odd, use only the bottom 8 bits of the key.
    Use XOR method"""
    # Ensure the input is a bytearray
    if isinstance(input_data, str):
        # Bytearray is like a list of bytes, but it is mutable
        input_data = bytearray(input_data, 'utf-8')
    elif not isinstance(input_data, bytearray):
        raise ValueError("input_data must be a string or a bytearray")

    # If the input don't have a length that is a multiple of 4, add 0 in left side
    while len(input_data) % 4 != 0:
        input_data.insert(0, 0)

    # Get the 8 lowest bits of the key by using AND with 11111111
    key_low_8 = key & 0xFF
    # Shift the key 8 bits to the right and get the 8 lowest bits
    key_high_8 = (key >> 8) & 0xFF

    # For final result with all the blocks
    result = bytearray()

    # Process the data in blocks of 4 bytes
    for i in range(0, len(input_data), 4):
        # Get the next block of 4 bytes
        block = input_data[i:i + 4]

        # Step 1: XOR each pair of bytes with the key
        block_after_xor = bytearray()
        # Because the key is 16 bits , doing XOR 8 bits with 8 bits because XOR is on same size operands
        for j in range(4):
            xor_result = block[j] ^ (key_high_8 if j % 2 == 0 else key_low_8)
            block_after_xor.append(xor_result)

        # Step 2: Replace each byte using the Look Up Table by list comprehension
        block_after_lookup = bytearray()
        for b in block_after_xor:
            block_after_lookup.append(lookup_table[b])

        # Step 3: Do a cyclic shift of the block , the last byte becomes the first
        block_after_cyclic = block_after_lookup[-1:] + block_after_lookup[:-1]

        # Step 4: XOR the shifted block again with the key
        block_final = bytearray()
        for j in range(4):
            xor_result = block_after_cyclic[j] ^ (key_high_8 if j % 2 == 0 else key_low_8)
            block_final.append(xor_result)

        # Add the encrypted block to the result , need extend and not append because
        # [A,B].append([C,D]) will result in [A,B,[C,D]] and not [A,B,C,D]
        result.extend(block_final)

    # Return the result as bytes , because until the decryption the data is bytes
    return bytes(result)

def symmetric_decryption(encrypt_data,key):
    """Return the encrypted / decrypted data
    The key is 16 bits. If the length of the input data is odd, use only the bottom 8 bits of the key.
    Use XOR method"""
    # Ensure the input is a bytearray
    if isinstance(encrypt_data, bytes):
        # Bytearray is like a list of bytes, but it is mutable
        encrypt_data = bytearray(encrypt_data)
    elif not isinstance(encrypt_data, bytearray):
        raise ValueError("input_data must be a string or a bytearray")

    # To final decrypt
    result = bytearray()

    key_low_8 = key & 0xFF
    key_high_8 = (key >> 8) & 0xFF

    # If someone change the len of the data , that not a multiple of 4 , don't do the decryption , because in the
    # encryption we sure that the data is a multiple of 4 by adding 0 in the left side
    if len(encrypt_data) % 4 != 0:
        return "It's not a real data , I go out"

    for i in range(0,len(encrypt_data),4):
        # Get the block
        block = encrypt_data[i:i + 4]

        # Stage 1 - do XOR with the key
        block_after_xor = bytearray()
        for j in range(4):
            xor_result = block[j] ^ (key_high_8 if j % 2 == 0 else key_low_8)
            block_after_xor.append(xor_result)

        # Stage 2 - do a left cyclic shift of the block , the first be last
        block_after_left_cyclic_shift = block_after_xor[1:] + block_after_xor[:1]

        # Stage 3 - do revers look uo table
        # The index in lookup table of the value in block_after_left_cyclic_shift
        # is the reverse ([50] = 70, index(70) = 50)
        block_after_revers_lookup_table = bytearray()
        for b in block_after_left_cyclic_shift:
            block_after_revers_lookup_table.append(lookup_table.index(b))


        # Stage 4 - do XOR with the key
        block_final_decrypt = bytearray()
        for j in range(4):
            xor_result = block_after_revers_lookup_table[j] ^ (key_high_8 if j % 2 == 0 else key_low_8)
            block_final_decrypt.append(xor_result)

        # Add the block to the result
        result.extend(block_final_decrypt)

    # Input the message without the padding if have
    real_result = result.lstrip(b'\x00')
    return real_result.decode('utf-8')



def diffie_hellman_choose_private_key():
    """Choose a 16 bit size private key """
    return random.randint(1, 2 ** 16 - 1)


def diffie_hellman_calc_public_key(private_key):
    """G**private_key mod P"""
    return (DIFFIE_HELLMAN_G ** private_key) % DIFFIE_HELLMAN_P


def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    """other_side_public**my_private mod P"""
    return (other_side_public ** my_private) % DIFFIE_HELLMAN_P


def calc_hash(message):
    """Create some sort of hash from the message
    Result must have a fixed size of 16 bits"""
    # The maximum value of a 16 bit number for the range of 16 bits
    max_16_bit_size = 2 ** 16
    prime = 31
    hash = 0
    for char in (message):
        hash += hash * prime + ord(char)

    return hash % max_16_bit_size


def calc_signature(hash, RSA_private_key,N):
    """Calculate the signature, using RSA alogorithm
    hash**RSA_private_key mod (P*Q)"""
    return pow(hash, RSA_private_key, N)


def create_msg(data):
    """Create a valid protocol message, with length field
    For example, if data = data = "hello world",
    then "11hello world" should be returned"""
    data_len = str(len(data))
    # Add leading zeros to the length field if the length is less than LENGTH_FIELD_SIZE (2)
    data_len_filled = data_len.zfill(LENGTH_FIELD_SIZE)

    # If the data is a string, like in send public keys
    if isinstance(data, str):
        return data_len_filled + data

    # If the data is a bytes, like in send encrypted message
    if isinstance(data, bytes):
        # Len field is a string , so encode the data
        return data_len_filled.encode() + data


def get_msg(my_socket):
    """Extract message from protocol, without the length field
       If length field does not include a number, returns False, "Error" """
    try:
        # Extract the length of the data from the message
        len = my_socket.recv(LENGTH_FIELD_SIZE).decode()

        # If length field is uncorrected
        if not len:
            return False, "Error"

        # Read the data by the len value and decode it
        len = int(len)

        # If the data is a string, like in send public keys
        if isinstance(my_socket, str):
            message = my_socket.recv(len).decode()

        else:
            # If the data is a bytes, like in send encrypted message
            # Only after decrypting the message we decode it , because the encrypted
            message = my_socket.recv(len)

        return True, message
    # If the client close the connection in unexpected way
    except ConnectionResetError:
        print("The client is disconnected , the connection is closed")
        return False, "Error"


def is_prime(number):
    """Check if the num is prime"""
    for i in range(2,int(math.sqrt(number)) + 1):
        if number % i == 0:
            return False
    return True

def check_RSA_public_key(totient,public_key):
    """Check that the selected public key satisfies the conditions
    key is prime
    key < totoent
    totient mod key != 0"""
    if not is_prime(public_key):
        return False
    if public_key >= totient:
        return False
    if totient % public_key == 0:
        return False

    return True
    
    
def get_RSA_private_key(p, q, public_key):
    """Calculate the pair of the RSA public key.
    Use the condition: Private*Public mod Totient == 1
    Totient = (p-1)(q-1)"""
    T = (p - 1) * (q - 1)
    try_private_key = T // public_key
    while ((try_private_key * public_key) % T) != 1:
        try_private_key += 1

    return try_private_key


