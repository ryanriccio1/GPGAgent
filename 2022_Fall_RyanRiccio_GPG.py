# Author:   Ryan Riccio
# Program:  GPG Main Program
# Date:     November 17th, 2022
from gpg_encrypt import *
from gpg_decrypt import *
import argparse


parser = argparse.ArgumentParser("GPG Manager", description="En/decrypt a file using GPG", epilog="Output to file")
parser.add_argument("filename", help="file to en/decrypt")
parser.add_argument("-o", "--output", help="file to write encrypted data to")
# decrypt is default so running gpg.py [file] will perform main project functions
parser.add_argument("-m", "--mode", help="choose GPG mode", choices=["encrypt", "decrypt"], default="decrypt")
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
        output = bytes(args.output, 'utf-8')
    elif args.mode == "encrypt":
        output = bytes(f"{args.filename}.gpg", 'utf-8')
    else:
        output = None

    if args.mode == "encrypt":
        encrypt(args.filename, output, args.s2k_digest_algo, args.cipher_algo, args.s2k_mode, args.s2k_count)
    elif args.mode == "decrypt":
        decrypt(args.filename, output)

else:
    print("That file does not exist.")
