# Author:   Ryan Riccio
# Program:  GPG Packet Information/Values
# Date:     November 17th, 2022
import md5
import sha1
import sha2
import aes
import des


class AlgorithmInfo(object):
    def __init__(self, value, name, cls=None, key_len=0, block_len=0, sup_class="DES"):
        """
        Store information about a given algorithm.

        :param value: Value assigned in RFC.
        :param name: Pretty name of algorithm.
        :param cls: Reference to implementation of algorithm.
        :param key_len: Required key length.
        :param block_len: Internal block length.
        :param sup_class: Description of algorithm as part of group.
        """
        self.value = value
        self.name = name
        self.cls = cls
        self.key_len = key_len
        self.block_len = block_len
        self.sup_class = sup_class


class Tag(object):
    def __init__(self, value, name):
        """
        Store GPG tag data.

        :param value: Value of tag.
        :param name: Name of tag.
        """
        self.value = value
        self.name = name

    @property
    def value(self):
        return self._value

    @property
    def name(self):
        return self._name

    @value.setter
    def value(self, value):
        self._value = value

    @name.setter
    def name(self, value):
        self._name = value


# RFC 4880: 9.2
_sym_algorithm = {
    0: AlgorithmInfo(0, "Unencrypted Plaintext"),
    1: AlgorithmInfo(1, "IDEA"),
    2: AlgorithmInfo(2, "3DES", des.TDES, 24, 8, "DES"),
    3: AlgorithmInfo(3, "CAST5"),
    4: AlgorithmInfo(4, "Blowfish"),
    5: AlgorithmInfo(5, "Reserved"),
    6: AlgorithmInfo(6, "Reserved"),
    7: AlgorithmInfo(7, "AES128", aes.AES, 16, 16, "AES"),
    8: AlgorithmInfo(8, "AES192", aes.AES, 24, 16, "AES"),
    9: AlgorithmInfo(9, "AES256", aes.AES, 32, 16, "AES"),
    10: AlgorithmInfo(10, "Twofish")
}

sym_LUT = {
    "3DES": 2,
    "AES128": 7,
    "AES192": 8,
    "AES256": 9
}

# RFC 4880: 9.4
_hash_algorithm = {
    0: AlgorithmInfo(0, "Error/None"),
    1: AlgorithmInfo(1, "MD5", md5.MD5),
    2: AlgorithmInfo(2, "SHA1", sha1.SHA1),
    3: AlgorithmInfo(3, "RIPE-MD/160"),
    4: AlgorithmInfo(4, "Reserved"),
    5: AlgorithmInfo(5, "Reserved"),
    6: AlgorithmInfo(6, "Reserved"),
    7: AlgorithmInfo(7, "Reserved"),
    8: AlgorithmInfo(8, "SHA256", sha2.SHA256),
    9: AlgorithmInfo(9, "SHA384", sha2.SHA384),
    10: AlgorithmInfo(10, "SHA512", sha2.SHA512),
    11: AlgorithmInfo(11, "SHA224", sha2.SHA224),
}

hash_LUT = {
    "MD5": 1,
    "SHA1": 2,
    "SHA256": 8,
    "SHA384": 9,
    "SHA512": 10,
    "SHA224": 11
}

# RFC 4880: 4.3
tags = {
    0: Tag(0, "invalid"),
    1: Tag(1, "pubkey enc session"),
    2: Tag(2, "signature"),
    3: Tag(3, "symkey enc packet"),
    4: Tag(4, "one pass signature"),
    5: Tag(5, "secret key"),
    6: Tag(6, "public key"),
    7: Tag(7, "secret subkey"),
    8: Tag(8, "compressed data"),
    9: Tag(9, "sym enc data"),
    10: Tag(10, "marker"),
    11: Tag(11, "literal data"),
    12: Tag(12, "trust"),
    13: Tag(13, "user id"),
    14: Tag(14, "public subkey"),
    17: Tag(17, "user attribute"),
    18: Tag(18, "encrypted data packet"),
    19: Tag(19, "mod detection")
}


def get_sym_algorithm(value):
    """ Search for value in algorithms. """
    return _sym_algorithm.get(value, None)


def get_hash_algorithm(value):
    """ Search for value in algorithms. """
    return _hash_algorithm.get(value, None)


def get_tag(value):
    """ Search for value in tags. """
    return tags.get(value, None)
