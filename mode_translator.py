# Author:   Ryan Riccio
# Program:  GPG Encryption Algorithm Eum Mode Translator
# Date:     November 17th, 2022
from des import DESMode
from aes import AESMode


def get_mode(encryption_algorithm="DES"):
    """
    Convert generic mode to algorithm specific mode. This allows DES and AES to be self-contained,
    otherwise, there would be dependencies to a common mode module for each algorithm.

    :param encryption_algorithm: Name of algorithm being used.
    :return: Encryption mode enum.
    """
    if encryption_algorithm.upper() == "DES":
        return DESMode
    if encryption_algorithm.upper() == "AES":
        return AESMode
    return None
