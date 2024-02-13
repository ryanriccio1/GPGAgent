# Author:   Ryan Riccio
# Program:  GPG Symmetric Encryption Loop
# Date:     November 17th, 2022
import s2k
import sha1
import time
import os.path
import mode_translator
import gpg_packet.packet as packet
from gpg_packet.constructor import get_hlen


def encrypt(filename, out_file, hash_algorithm, encryption_algorithm, s2k_mode, s2k_count):
    """
    Encrypt a file using GPG.

    :param filename: File to encrypt.
    :param out_file: File to write to.
    :param hash_algorithm: Algorithm to use with S2K.
    :param encryption_algorithm: Algorithm to use for encryption
    :param s2k_mode: Mode to use for key generation.
    :param s2k_count: Count to use in S2K mode 3.
    """
    print("Encrypting...")
    # generate s2k packet (data validation is better when we generate our packet, and we can use it later)
    s2k_packet = _generate_s2k_packet(s2k_mode, encryption_algorithm, hash_algorithm, s2k_count)

    # get the encryption algorithm and hash algorithm from generated packet
    encryption_algorithm = s2k_packet.data.encryption_algorithm
    hash_algorithm = s2k_packet.data.hash_algorithm

    # get S2K info from packet (this performs logic on the packet)
    salt, count = s2k.get_salt_count(s2k_packet, s2k_mode)

    # calculate key
    password = s2k.get_pass()
    key_len = encryption_algorithm.key_len
    key = bytes.fromhex(s2k.calculate_s2k(password, s2k_mode, key_len, hash_algorithm.value, salt, count))

    # generate the literal data to encrypt, store it to a packet
    data_to_encrypt = _generate_literal_data(filename, encryption_algorithm)
    sym_enc_packet = _generate_enc_packet(data_to_encrypt, key, encryption_algorithm)

    # write packets to file
    with open(out_file, 'wb') as file:
        file.write(s2k_packet.header.byte_form)
        file.write(s2k_packet.data.data)
        file.write(sym_enc_packet.header.byte_form)
        file.write(sym_enc_packet.data.data)

    print(f"Encryption Algorithm: {encryption_algorithm.name}")
    print(f"S2K Mode: {s2k_mode}")
    if count:
        print(f"S2K Count: {count}")
    print(f"Key Hash: {hash_algorithm.name}")
    print(f"SUCCESS: Encrypted file written to {out_file.decode('utf-8')}.")


def _generate_s2k_packet(s2k_mode, encryption_algorithm, hash_algorithm, s2k_count):
    """ Generate S2K packet from user entered values. """
    # convert user values to actual packet data
    s2k_packet_data, salt = s2k.generate_packet(s2k_mode, encryption_algorithm, hash_algorithm, s2k_count)
    # use packet to generate header
    plen = len(s2k_packet_data.data)
    hlen = get_hlen(plen)
    s2k_packet_header = packet.PacketHeader(0, b"\x00", tag=3, hlen=hlen, plen=plen, new=False)
    # combine to create packet and return
    s2k_packet = packet.Packet(s2k_packet_header, s2k_packet_data)
    return s2k_packet


def _generate_literal_data(filename, encryption_algorithm):
    """ Create data from file to encrypt. """
    # use salter to get data
    random_starting_data = s2k.generate_salt(encryption_algorithm.block_len)
    random_starting_data += random_starting_data[-2:]

    # read in file contents (0x62 is byte mode)
    # byte mode + filename length + filename + epoch file time (4 bytes) + file data
    with open(filename, 'rb') as file:
        lit_data = b"\x62" + len(filename).to_bytes(1, byteorder='big') + \
                   bytes(filename, 'ascii') + int(time.time()).to_bytes(4, byteorder='big') + file.read()

    # generate packet header for literal data packet
    plen = len(lit_data)
    hlen = get_hlen(plen)
    lit_data_header = packet.PacketHeader(0, b"\x00", tag=11, hlen=hlen, plen=plen, new=False)
    lit_header_bytes = lit_data_header.byte_form

    # add random data to beginning of literal data packet (tag 11) and header of MDC packet
    data_to_encrypt = bytes(random_starting_data + lit_header_bytes + lit_data + b"\xd3\x14")

    # add MDC packet
    data_to_encrypt += bytes.fromhex(sha1.SHA1().hash(data_to_encrypt))
    return data_to_encrypt


def _generate_enc_packet(data, key, encryption_algorithm):
    """ Convert encrypted data to packet. """
    # encrypt in GPG mode
    encrypter = encryption_algorithm.cls()
    encrypter.mode = mode_translator.get_mode(encryption_algorithm.sup_class).GPG
    encrypter.key = key
    encrypter.iv = b"\x00" * encryption_algorithm.block_len

    # append version 1 (only version) and create header and packet
    sym_enc_data = packet.PacketData(b"\x01" + encrypter.encrypt(data))
    sym_enc_header = packet.PacketHeader(0, b"\x00", tag=18, hlen=0, plen=len(sym_enc_data.data), new=True)
    return packet.Packet(sym_enc_header, sym_enc_data)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser("GPG Encrypter", description="Encrypt a file using GPG", epilog="Output to file")
    parser.add_argument("filename", help="file to encrypt")
    parser.add_argument("-o", "--output", help="file to write to")
    parser.add_argument("--cipher-algo", help="algorithm to encrypt with",
                        choices=["3DES", "AES128", "AES192", "AES256"], default="AES256")
    parser.add_argument("--s2k-mode", help="mode for s2k", type=int, choices=[0, 1, 3], metavar="[0, 1, 3]", default=3)
    parser.add_argument("--s2k-digest-algo", help="hash to use for S2K",
                        choices=["MD5", "SHA1", "SHA256", "SHA384", "SHA512", "SHA224"], default="SHA256")
    parser.add_argument("--s2k-count", help="count to use for S2K", type=int, default=65536, metavar="[1024-65011712]")
    args = parser.parse_args()
    if os.path.exists(args.filename):
        if 1024 > args.s2k_count > 65011712:
            print("S2K Count out of range.")
            exit(1)
        if args.output:
            output = args.output
        else:
            output = f"{args.filename}.gpg"

        encrypt(args.filename, output, args.s2k_digest_algo, args.cipher_algo, args.s2k_mode, args.s2k_count)
