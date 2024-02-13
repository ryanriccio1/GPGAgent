# Author:   Ryan Riccio
# Program:  SHA1 Hash Implementation
# Date:     November 17th, 2022
class SHA1(object):
    def __init__(self, data=None):
        """
        Class to hash data using SHA1

        :param data: Data to hash.
        """
        self.DESIRED_BYTE_LENGTH = 8

        self._H0 = 0x67452301
        self._H1 = 0xEFCDAB89
        self._H2 = 0x98BADCFE
        self._H3 = 0x10325476
        self._H4 = 0xC3D2E1F0

        self.data = data

    @property
    def data(self):
        """
        Data to hash.

        :return: Data to hash.
        """
        return self._data

    @data.setter
    def data(self, value):
        """
        Data to hash.

        :param value: Data to hash.
        :return: None
        :rtype: None
        """
        if value:
            if isinstance(value, str):
                self._data = bytearray(value, 'utf-8')
            else:
                self._data = bytearray(value)

    def hash(self, data=None):
        """
        Hash data using the SHA1 hash function.

        :param data: Data to hash.
        :return: Hash in hex.
        :rtype: str
        """
        # if the user specified data when calling hash(), prioritize that
        if data:
            self.data = data
        elif not self.data:
            raise ValueError("No data to hash.")

        # add padding
        bit_len = (8 * len(self.data))
        self.data.append(0x80)
        while (len(self.data) * 8) % 512 != 448:
            self.data.append(0)
        self.data += bit_len.to_bytes(8, byteorder="big")

        # split to 512-bit blocks
        for block in self._nsplit(self.data, 64):
            chunks = [int.from_bytes(chunk, byteorder="big") for chunk in self._nsplit(block, 4)]

            for i in range(16, 80):
                chunks.append(self._rol((chunks[i-3] ^ chunks[i-8] ^ chunks[i-14] ^ chunks[i-16]), 1))

            a = self._H0
            b = self._H1
            c = self._H2
            d = self._H3
            e = self._H4

            for i in range(80):
                if 0 <= i <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= i <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= i <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= i <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = self._rol(a, 5) + f + e + k + chunks[i]
                temp &= 0xFFFFFFFF
                e = d
                d = c
                c = self._rol(b, 30)
                b = a
                a = temp

            # 32-bit modular add
            self._H0 += a
            self._H0 &= 0xFFFFFFFF
            self._H1 += b
            self._H1 &= 0xFFFFFFFF
            self._H2 += c
            self._H2 &= 0xFFFFFFFF
            self._H3 += d
            self._H3 &= 0xFFFFFFFF
            self._H4 += e
            self._H4 &= 0xFFFFFFFF

        # convert digest to hex string and return
        digest = (self._H0 << 128) | (self._H1 << 96) | (self._H2 << 64) | (self._H3 << 32) | self._H4
        return hex(digest)[2:].zfill(40)

    def _nsplit(self, data, split_size=64):
        """
        Splits data into equal sections of 'split_size' length. (default=64)
        Asymmetrical data will yield the last section being shorter.

        :param data: data to be split
        :param int split_size: size of each yielded split
        :return: iterator which gives data block
        :rtype: generator
        """
        for idx in range(0, len(data), split_size):
            yield data[idx:idx + split_size]

    def _rol(self, data, amount):
        """
        32-bit rotate left command.

        :param data: Data to rotate.
        :param amount: Amount to rotate by.
        :return: Rotated data.
        """
        return ((data << amount) | (data >> (32 - amount))) & 0xFFFFFFFF
