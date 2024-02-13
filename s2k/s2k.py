# Author:   Ryan Riccio
# Program:  S2K Processing
# Date:     November 17th, 2022
from gpg_packet.packet_consts import *
from gpg_packet.packet import *
from getpass import getpass
import secrets


# RFC 4880: 3.7.1
def calculate_s2k(password, s2k_mode, key_length, hash_algorithm, salt=None, count=65536):
    """
    Generate a Key from a user password

    :param password: Password to convert to hash.
    :param s2k_mode: Mode to use for S2K.
    :param key_length: Length of key used in encryption algorithm.
    :param hash_algorithm: Hash to use to generate key.
    :param salt: Salt to use in mode 1 and 3.
    :param count: Number of octets of data to hash in mode 3.
    :return: Key
    """
    # RFC 4880: 3.7.1
    if s2k_mode == 0 or s2k_mode == 1 or s2k_mode == 3:
        if s2k_mode == 1 or s2k_mode == 3:
            # RFC 4880: 3.7.1.2
            password = salt + password
        if s2k_mode == 3:
            # RFC 4880: 3.7.1.3
            if len(password) < count:
                while len(password) < count:
                    password += password
                password = password[:count]

        key = ""
        looped = False
        while len(key) < key_length * 2:
            if looped:
                # RFC 4880: 3.7.1.1
                password = b"\x00" + password
            key += get_hash_algorithm(hash_algorithm).cls().hash(password)
            looped = True
    else:
        raise ValueError(f"Invalid S2K mode '{s2k_mode}'")
    return key[:key_length * 2]


def decode_count(count):
    """ Perform EXPBIAS 6 macro as defined in the RFC. """
    # RFC 4880: 3.7.1.3
    return (16 + (count & 15)) << ((count >> 4) + 6)


def encode_count(iterations=65535):
    """ Inverse of EXPBIAS 6 in RFC (found in libcrypt S2K). """
    if iterations < 1024:
        iterations = 1024
    if iterations >= 65011712:
        return 255

    c = 0
    count = iterations >> 6

    while count >= 32:
        c += 1
        count >>= 1

    result = (c << 4) | (count - 16)
    if decode_count(result) < iterations:
        result += 1
    return result


def get_salt_count(s2k_packet, s2k_mode):
    """
    Extract the salt and count from an S2K packet. This will handle modes.
    This allows for mode logic to be done "behind the scenes".

    :param s2k_packet: Packet to extract from.
    :param s2k_mode: Mode being used.
    :return: Salt and count.
    """
    if s2k_mode == 0:
        salt = None
        count = None
    if s2k_mode == 1 or s2k_mode == 3:
        salt = s2k_packet.data.salt
        count = None
    if s2k_mode == 3:
        count = decode_count(s2k_packet.data.count)
    return salt, count


def generate_packet(s2k_mode, encryption_algorithm, hash_algorithm, count=65536):
    """
    Given information about GPG encryption session, generate S2K packet.

    :param s2k_mode: S2K mode to use.
    :param encryption_algorithm: Name of encryption algorithm to use.
    :param hash_algorithm: Name of hash algorithm to use.
    :param count: Value of count to use.
    :return: Packet and salt value.
    """
    salt = generate_salt()
    # if the encryption algorithm exists, get the value
    if encryption_algorithm := sym_LUT.get(encryption_algorithm):
        # if the hash algorithm exists, get the value
        if hash_algorithm := hash_LUT.get(hash_algorithm):
            # based on S2K mode, generate the PacketData
            if s2k_mode == 0:
                packet = PacketS2K0(encryption_algorithm, hash_algorithm)
            elif s2k_mode == 1:
                packet = PacketS2K1(encryption_algorithm, hash_algorithm, salt)
            elif s2k_mode == 3:
                packet = PacketS2K3(encryption_algorithm, hash_algorithm, salt, encode_count(count))
            else:
                raise ValueError("S2K Mode is invalid.")
            return packet, salt
        raise ValueError("That is an invalid hash algorithm.")
    raise ValueError("That is an invalid encryption algorithm.")


def generate_salt(length=8):
    """
    Generate random salt data of a given length.

    :param int length: Amount of salt to generate.
    :return: Salt value.
    """
    return secrets.token_bytes(length)


def get_pass():
    """
    Get user input without writing to screen.

    :return: Password.
    """
    return bytes(getpass(), 'utf-8')


passphrase = "test"
s2k_m0_key = "098f6bcd4621d373cade4e83" + \
             "2627b4f65f8f8e05efdc22e8"

assert calculate_s2k(bytes(passphrase, "utf-8"), s2k_mode=0, key_length=24, hash_algorithm=1) == s2k_m0_key
