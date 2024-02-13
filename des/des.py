# Author:   Ryan Riccio
# Program:  DES Main Class
# Date:     November 17th, 2022
from des.des_core import DESCore
from enum import Enum


class DESMode(Enum):
    ECB = 1
    CBC = 2
    OFB = 3
    GPG = 4

    @staticmethod
    def get_mode(mode):
        match(mode.upper()):
            case "ECB":
                return DESMode.ECB
            case "CBC":
                return DESMode.CBC
            case "OFB":
                return DESMode.OFB
            case "GPG":
                return DESMode.GPG
            case _:
                raise ValueError("Mode must be 'ECB', 'CBC', or 'OFB'.")


class DESError(Exception):
    pass


class DES(DESCore):
    def __init__(self, key=None, mode=DESMode.ECB, iv=None):
        """
        Class to encrypt or decrypt data using the DES algorithm.

        :param bytes key: Key to use for En/Decryption.
        :param DESMode mode: Mode to use for En/Decryption.
        :param bytes iv: DES initialization vector.
        :return: DES Class instance
        :rtype: DES
        """
        super().__init__()
        self.key = key
        self.mode = mode
        if self.mode != DESMode.ECB:
            self.iv = iv

    # region Properties
    @property
    def key(self):
        """
        Value of the key for the DES algorithm.

        :return: Value of the DES key.
        :rtype: bytes
        """
        return self._key

    @property
    def mode(self):
        """
        Value of the mode for the DES algorithm.

        :return: Mode of the DES module.
        :rtype: DESMode
        """
        return self._mode

    @property
    def iv(self):
        """
        Value of the IV for the DES module.

        :return: Initialization Vector of the DES module.
        :rtype: bytes
        """
        return self._iv

    @key.setter
    def key(self, value):
        """
        Key for DES module.

        :param bytes value: Value to set the key to.
        """
        if value:
            if not isinstance(value, bytes):
                raise DESError("Key must be in byte form.")
            if len(value) != 8:
                raise DESError("Key must be 8-bytes long.")

        self._key = value

    @mode.setter
    def mode(self, value):
        """
        Mode for DES module.

        :param value: Value to set the mode to ("ECB", "CBC", "OFB", or DESMode Enum).
        """
        if isinstance(value, str):
            self._mode = DESMode.get_mode(value)
        elif isinstance(value, DESMode):
            self._mode = value
        else:
            raise DESError("Mode must be str or DESMode Enum.")

    @iv.setter
    def iv(self, value):
        """
        IV for DES module.

        :param bytes value: Value to set the IV to.
        """
        if value:
            if not isinstance(value, bytes):
                raise DESError("IV must be in byte form.")
            # allow stream
            if self.mode == DESMode.ECB or self.mode == DESMode.CBC:
                if len(value) != 8:
                    raise DESError("IV must be 8-bytes long.")
        self._iv = value
        self._iv_bits = self._bytes_to_bit_array(value)
    # endregion

    def encrypt(self, data):
        """
        Encrypt data using DES.

        :param bytes data: data to encrypt.
        :return: ciphertext
        :rtype: bytes
        """
        # make sure we are encrypting bytes
        if not isinstance(data, bytes):
            raise DESError("Data to encrypt must be in byte form.")

        if self.mode == DESMode.ECB or self.mode == DESMode.CBC:
            data = self._add_padding(data)
        plaintext = self._bytes_to_bit_array(data)
        ciphertext = []
        sub_keys = self._generate_sub_keys(self.key)

        for pt_block in self._nsplit(plaintext, 64):
            if self.mode == DESMode.ECB:
                # encrypt 64 bits at a time
                ciphertext += self._crypt_block(pt_block, sub_keys)
            if self.mode == DESMode.CBC:
                temp_block = self._xor(pt_block, self._iv_bits)
                self._iv_bits = self._crypt_block(temp_block, sub_keys)
                ciphertext += self._iv_bits
            if self.mode == DESMode.OFB:
                self._iv_bits = self._crypt_block(self._iv_bits, sub_keys)
                ciphertext += self._xor(pt_block, self._iv_bits)
            if self.mode == DESMode.GPG:
                return DESError("GPG Mode is only support in 3DES.")

        ciphertext = self._bit_array_to_bytes(ciphertext)
        return ciphertext

    def decrypt(self, data):
        """
        Decrypt data using DES.

        :param bytes data: data to decrypt.
        :return: plaintext
        :rtype: bytes
        """
        # make sure we are decrypting bytes
        if not isinstance(data, bytes):
            raise DESError("Data to decrypt must be in byte form.")

        ciphertext = self._bytes_to_bit_array(data)
        plaintext = []

        if self.mode == DESMode.ECB or self.mode == DESMode.CBC:
            sub_keys = list(reversed(self._generate_sub_keys(self.key)))
        else:
            sub_keys = self._generate_sub_keys(self.key)

        for ct_block in self._nsplit(ciphertext, 64):
            if self.mode == DESMode.ECB:
                # encrypt 64 bits at a time
                plaintext += self._crypt_block(ct_block, sub_keys)
            if self.mode == DESMode.CBC:
                temp_block = self._crypt_block(ct_block, sub_keys)
                plaintext += self._xor(temp_block, self._iv_bits)
                self._iv_bits = ct_block
            if self.mode == DESMode.OFB:
                self._iv_bits = self._crypt_block(self._iv_bits, sub_keys)
                plaintext += self._xor(ct_block, self._iv_bits)
            if self.mode == DESMode.GPG:
                return DESError("GPG Mode is only support in 3DES.")

        plaintext = self._bit_array_to_bytes(plaintext)
        if self.mode == DESMode.ECB or self.mode == DESMode.CBC:
            plaintext = self._rem_padding(plaintext)
        return plaintext

    def reset(self):
        """
        Reset the IV back to what was previously set by the user.

        :return: None
        :rtype: None
        """
        self.iv = self._iv

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


class TDES(DES):
    @property
    def key(self):
        """
        Value of the key for the DES algorithm.

        :return: Value of the DES key.
        :rtype: bytes
        """
        # needed to overload key setter
        # call the getter from the base class
        return super().key

    @key.setter
    def key(self, value):
        """
        Key for DES module.

        :param bytes value: Value to set the key to.
        """
        # allow 192-bit keys as well
        if value:
            if len(value) == 8:
                self._key = value * 3
            elif len(value) == 24:
                self._key = value
            else:
                raise DESError("Key length must be 64-bits or 192-bits.")

    def encrypt(self, data):
        """
        Encrypt data using DES.

        :param bytes data: data to encrypt.
        :return: ciphertext
        :rtype: bytes
        """
        if not isinstance(data, bytes):
            raise DESError("Data to encrypt must be in byte form.")

        if self.mode == DESMode.GPG:
            return self._gpg_encrypt(data)

        if self.mode == DESMode.ECB or self.mode == DESMode.CBC:
            data = self._add_padding(data)
        plaintext = self._bytes_to_bit_array(data)
        ciphertext = []
        sub_keys = [self._generate_sub_keys(key) for key in self._nsplit(self.key, 8)]
        sub_keys[1] = list(reversed(sub_keys[1]))

        # TDES encryption
        for pt_block in self._nsplit(plaintext, 64):
            if self.mode == DESMode.ECB:
                # encrypt 64 bits at a time
                ct_block = pt_block
                for i in range(3):
                    ct_block = self._crypt_block(ct_block, sub_keys[i])
                ciphertext += ct_block

            if self.mode == DESMode.CBC:
                self._iv_bits = self._xor(pt_block, self._iv_bits)
                for i in range(3):
                    self._iv_bits = self._crypt_block(self._iv_bits, sub_keys[i])
                ciphertext += self._iv_bits

            if self.mode == DESMode.OFB:
                for i in range(3):
                    self._iv_bits = self._crypt_block(self._iv_bits, sub_keys[i])
                ciphertext += self._xor(pt_block, self._iv_bits)

        ciphertext = self._bit_array_to_bytes(ciphertext)
        return ciphertext

    def decrypt(self, data):
        """
        Decrypt data using DES.

        :param bytes data: data to decrypt.
        :return: plaintext
        :rtype: bytes
        """
        if not isinstance(data, bytes):
            raise DESError("Data to decrypt must be in byte form.")

        if self.mode == DESMode.GPG:
            return self._gpg_decrypt(data)

        ciphertext = self._bytes_to_bit_array(data)
        plaintext = []
        sub_keys = [self._generate_sub_keys(key) for key in self._nsplit(self.key, 8)]
        if self.mode == DESMode.ECB or self.mode == DESMode.CBC:
            sub_keys[0] = list(reversed(sub_keys[0]))
            sub_keys[2] = list(reversed(sub_keys[2]))
        else:
            sub_keys[1] = list(reversed(sub_keys[1]))

        # TDES Decryption
        for ct_block in self._nsplit(ciphertext, 64):
            if self.mode == DESMode.ECB:
                pt_block = ct_block
                for i in range(2, -1, -1):
                    pt_block = self._crypt_block(pt_block, sub_keys[i])
                plaintext += pt_block

            if self.mode == DESMode.CBC:
                pt_block = ct_block
                for i in range(2, -1, -1):
                    pt_block = self._crypt_block(pt_block, sub_keys[i])
                plaintext += self._xor(pt_block, self._iv_bits)
                self._iv_bits = ct_block

            if self.mode == DESMode.OFB:
                for i in range(3):
                    self._iv_bits = self._crypt_block(self._iv_bits, sub_keys[i])
                plaintext += self._xor(ct_block, self._iv_bits)

        plaintext = self._bit_array_to_bytes(plaintext)
        if self.mode == DESMode.ECB or self.mode == DESMode.CBC:
            plaintext = self._rem_padding(plaintext)
        return plaintext

    def _gpg_encrypt(self, plaintext):
        """ 'Hack' OFB mode into processing GPG packets in modified CFB mode."""
        self.mode = DESMode.OFB
        first_block = self.encrypt(plaintext[:8])
        self.iv = first_block
        second_block = self.encrypt(plaintext[8:16])
        self.iv = second_block

        ct = b""
        for block in self._nsplit(plaintext[16:], 8):
            ct_block = self.encrypt(block)
            ct += ct_block
            self.iv = ct_block
        return first_block + second_block + ct

    def _gpg_decrypt(self, ciphertext):
        """ 'Hack' OFB mode into processing GPG packets in modified CFB mode."""
        self.mode = DESMode.OFB
        first_block = self.decrypt(ciphertext[:8])
        self.iv = ciphertext[:8]
        second_block = self.decrypt(ciphertext[8:16])
        self.iv = ciphertext[8:16]

        if first_block[-2:] != second_block[:2]:
            raise DESError("The key is incorrect!")

        pt = b""
        for block in self._nsplit(ciphertext[16:], 8):
            pt += self.decrypt(block)
            self.iv = block
        return first_block + second_block + pt

