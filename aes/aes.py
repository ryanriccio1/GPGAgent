# Author:   Ryan Riccio
# Program:  AES Main Class
# Date:     November 17th, 2022
from aes.aes_core import AESCore
from enum import Enum


class AESMode(Enum):
    ECB = 1
    CBC = 2
    OFB = 3
    GPG = 4

    @staticmethod
    def get_mode(mode):
        match (mode.upper()):
            case "ECB":
                return AESMode.ECB
            case "CBC":
                return AESMode.CBC
            case "OFB":
                return AESMode.OFB
            case "GPG":
                return AESMode.GPG
            case _:
                raise ValueError("Mode must be 'ECB', 'CBC', or 'OFB'.")


class AESError(Exception):
    pass


class AES(AESCore):
    def __init__(self, key=None, mode=AESMode.ECB,
                 iv=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"):
        """
        Class to encrypt or decrypt data using the AES algorithm.

        :param bytes key: Key to use for En/Decryption.
        :param AESMode mode: Mode to use for En/Decryption.
        :param bytes iv: AES initialization vector.
        :return: AES Class instance
        :rtype: AES
        """
        super().__init__()
        self.key = key
        self.mode = mode
        self.iv = iv

    # region Properties
    @property
    def key(self):
        """
        128, 192, or 256-bit key for AES.

        :return: AES Key.
        :rtype: bytes
        """
        return self._key

    @property
    def mode(self):
        """
        Mode of AES class.

        :return: Current mode of AES class.
        :rtype: AESMode
        """
        return self._mode

    @property
    def iv(self):
        """
        AES Initialization Vector.

        :return: AES Initialization Vector.
        :rtype: bytes
        """
        return self._iv

    @key.setter
    def key(self, value):
        """
        128, 192, or 256-bit key to use for AES.

        :param bytes value: Key to use for AES.
        :return: None
        :rtype: None
        """
        if value:
            if not isinstance(value, bytes):
                raise AESError("Key must be in byte form.")
            if len(value) % 4 != 0:
                raise AESError("Key must be divsible by 32-bits.")
            if 16 >= len(value) >= 32:
                raise AESError("Key must be between 128-256 bits.")
            self._rounds = self.rounds[len(value)]
            self._keys = self._generate_keys(value)
        self._key = value

    @mode.setter
    def mode(self, value):
        """
        Mode to use with AES (ECB, CBC, OFB, CFB).

        :param AESMode value: Mode to use with AES.
        :return: None
        :rtype: None
        """
        if isinstance(value, str):
            self._mode = AESMode.get_mode(value)
        elif isinstance(value, AESMode):
            self._mode = value
        else:
            raise AESError("Mode must be str or AESMode Enum.")

    @iv.setter
    def iv(self, value):
        """
        128-bit (16 byte) IV to use for AES.

        :param bytes value: IV to use for AES.
        :return: None
        :rtype: None
        """
        if value:
            # allow stream
            if self.mode == AESMode.ECB or self.mode == AESMode.CBC:
                if len(value) != 16:
                    raise AESError("IV must be 16 bytes long.")
            if not isinstance(value, bytes):
                raise AESError("IV must be in byte form.")
        self._iv = value

    # endregion

    # http://www.crypto-it.net/eng/theory/modes-of-block-ciphers.html
    def encrypt(self, data):
        """
        Encrypt data using AES.

        :param bytes data: data to encrypt.
        :return: ciphertext
        :rtype: bytes
        """
        if not isinstance(data, bytes):
            raise AESError("Data to decrypt must be in byte form.")

        if self.mode == AESMode.GPG:
            return self._gpg_encrypt(data)

        if self.mode == AESMode.ECB or self.mode == AESMode.CBC:
            data = self._add_padding(data)
        ciphertext = b""

        last_block = self.iv
        # encrypt data in 128-bit blocks
        for pt_block in self._nsplit(data, 16):
            if self.mode == AESMode.ECB:
                ciphertext += self._encrypt_block(pt_block)
            if self.mode == AESMode.CBC:
                ct_block = self._encrypt_block(self._xor(pt_block, last_block))
                ciphertext += ct_block
                last_block = ct_block
            if self.mode == AESMode.OFB:
                ct_block = self._encrypt_block(last_block)
                ct_block = self._xor(pt_block, ct_block)
                ciphertext += ct_block
                last_block = ct_block
            # if self.mode == AESMode.CBC:
            #     ct_block = self._xor(pt_block, self._encrypt_block(last_block))
            #     ciphertext += ct_block
            #     last_block = ct_block

        return ciphertext

    def decrypt(self, data):
        """
        Decrypt data using AES.

        :param bytes data: data to decrypt.
        :return: plaintext
        :rtype: bytes
        """
        if not isinstance(data, bytes):
            raise AESError("Data to decrypt must be in byte form.")

        if self.mode == AESMode.GPG:
            return self._gpg_decrypt(data)

        # assuming data is already encrypted, it must be padded and therefore
        # a multiple of 128-bits
        if self.mode == AESMode.ECB or self.mode == AESMode.CBC:
            if len(data) % 16 != 0:
                raise AESError("Data to decrypt must be a multiple of 128-bits.")

        plaintext = b""

        last_block = self.iv
        # decrypt data in 128-bit blocks
        for ct_block in self._nsplit(data, 16):
            if self.mode == AESMode.ECB:
                plaintext += self._decrypt_block(ct_block)
            if self.mode == AESMode.CBC:
                plaintext += self._xor(last_block, self._decrypt_block(ct_block))
                last_block = ct_block
            if self.mode == AESMode.OFB:
                temp_block = self._encrypt_block(last_block)
                pt_block = self._xor(ct_block, temp_block)
                plaintext += pt_block
                last_block = temp_block
            # if self.mode == AESMode.CBC:
            #     pt_block = self._xor(ct_block, self._encrypt_block(last_block))
            #     plaintext += pt_block
            #     last_block = ct_block

        if self.mode == AESMode.ECB or self.mode == AESMode.CBC:
            plaintext = self._rem_padding(plaintext)
        return plaintext

    def as_hex(self, *args, **kwargs):
        """
        Return byte string in hex.

        :argument: (pos arg) data to print.
        :key encrypted: bytestring to print.
        :type encrypted: bytes
        :key block: block of bits to print.
        :type block: list[int]
        :key length: length for zfill.
        :type length: int
        :return: string of hex data.
        :rtype: str
        """
        if args:
            # can print either bytes or list of bits
            if isinstance(args[0], bytes):
                block = self._bytes_to_bit_array(args[0])
            elif isinstance(args[0], list):
                block = args[0]
            else:
                raise ValueError("Invalid data input.")
        else:
            if 'block' in kwargs:
                block = kwargs['block']
            elif 'encrypted' in kwargs:
                block = self._bytes_to_bit_array(kwargs['encrypted'])
            else:
                raise ValueError("No data was given.")

        # get specific length
        if 'length' in kwargs:
            length = kwargs['length']
        else:
            length = len(block) // 4

        strings = [str(bit) for bit in block]
        byte = int("".join(strings), 2)
        data = hex(byte)[2:].zfill(length)
        return data

    def _gpg_encrypt(self, plaintext):
        """ 'Hack' OFB mode into processing GPG packets in modified CFB mode."""
        self.mode = AESMode.OFB
        first_block = self.encrypt(plaintext[:16])
        self.iv = first_block
        second_block = self.encrypt(plaintext[16:32])
        self.iv = second_block

        ct = b""
        for block in self._nsplit(plaintext[32:], 16):
            ct_block = self.encrypt(block)
            ct += ct_block
            self.iv = ct_block
        return first_block + second_block + ct

    def _gpg_decrypt(self, ciphertext):
        """ 'Hack' OFB mode into processing GPG packets in modified CFB mode."""
        self.mode = AESMode.OFB
        first_block = self.decrypt(ciphertext[:16])
        self.iv = ciphertext[:16]
        second_block = self.decrypt(ciphertext[16:32])
        self.iv = ciphertext[16:32]

        if first_block[-2:] != second_block[:2]:
            raise AESError("The key is incorrect!")

        pt = b""
        for block in self._nsplit(ciphertext[32:], 16):
            pt += self.decrypt(block)
            self.iv = block
        return first_block + second_block + pt
