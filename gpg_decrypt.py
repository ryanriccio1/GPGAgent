# Author:   Ryan Riccio
# Program:  GPG Symmetric Decryption Loop
# Date:     November 17th, 2022
import sha1
import os.path
import s2k.s2k as s2k
import mode_translator
from datetime import datetime
import gpg_packet.parser as parser


def decrypt(filename, out_file=None):
    """
    Decrypt a file that was encrypted with GPG.

    :param filename: File to decrypt.
    :param out_file: File to write decrypted data to.
    """
    try:
        # run parser to get packets
        packets = parser.parse_file(filename)
    except ValueError:
        print("Error while reading file! File may not be encrypted?")
        exit(1)

    # categorize packets into 'S2K' and 'encrypted'
    packets = parser.categorize_packets(packets)

    # read s2k packet
    s2k_mode = packets["S2K"].data.mode
    encryption_algorithm = packets["S2K"].data.encryption_algorithm
    hash_algorithm = packets["S2K"].data.hash_algorithm

    # get salt and count (this function access packets and performs logic)
    salt, count = s2k.get_salt_count(packets["S2K"], s2k_mode)

    # generate key
    password = s2k.get_pass()
    key_len = encryption_algorithm.key_len
    key = bytes.fromhex(s2k.calculate_s2k(password, s2k_mode, key_len, hash_algorithm.value, salt, count))

    # GPG mode decryption
    decrypter = encryption_algorithm.cls()
    decrypter.mode = mode_translator.get_mode(encryption_algorithm.sup_class).GPG
    decrypter.key = key
    decrypter.iv = b"\x00" * encryption_algorithm.block_len

    try:
        # decrypt (ignoring first byte that is always 0x01)
        decrypted_data = decrypter.decrypt(packets["encrypted"].data.data[1:])
    except Exception as error:
        print(str(error))
        exit(1)

    # make sure our literal data is not tampered with MDC packet (no sense in creating packet for one comparison
    if bytes.fromhex(sha1.SHA1().hash(decrypted_data[:-20])) != decrypted_data[-20:]:
        print("WARNING: Data has been tampered with!")

    # split literal data packet into pieces of data for easier access
    packet = parser.process_literal_data(decrypted_data, encryption_algorithm)
    print(f"Encryption Algorithm: {encryption_algorithm.name}")
    print(f"S2K Mode: {s2k_mode}")
    if count:
        print(f"S2K Count: {count}")
    print(f"Key Hash: {hash_algorithm.name}")
    print(f"Filename: {packet.data.filename.decode('utf-8')}")
    print(f"File Date: {datetime.fromtimestamp(int.from_bytes(packet.data.file_time, byteorder='big'))}")
    print(f"File Contents: {packet.data.text}")

    # write data to a file with the filename specified in the literal data packet
    if not out_file:
        out_file = packet.data.filename
    with open(out_file, 'wb') as file:
        file.write(packet.data.text)

    print(f"Decrypted file created: {out_file.decode('utf-8')}")


if __name__ == '__main__':
    import argparse
    arg_parser = argparse.ArgumentParser("GPG Decrypter", description="Decrypt a file using GPG", epilog="Output to file")
    arg_parser.add_argument("filename", help="file to decrypt", type=str)
    args = arg_parser.parse_args()

    if os.path.exists(args.filename):
        decrypt(args.filename)
    else:
        print("That file does not exist.")
