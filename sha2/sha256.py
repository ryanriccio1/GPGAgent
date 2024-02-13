# Author:   Ryan Riccio
# Program:  SHA2 Hash Implementation
# Date:     November 17th, 2022
class SHA256(object):
    _k = (0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
          0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
          0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
          0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
          0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
          0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
          0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
          0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
          0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
          0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
          0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
          0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
          0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
          0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
          0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
          0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2)
    _h = (0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    def __init__(self, data=None):
        """
        Hash data using SHA-2.

        :param data: Data to hash.
        """
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
        Hash data using the SHA-2 hash function.

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
            w = [int.from_bytes(chunk, byteorder="big") for chunk in self._nsplit(block, 4)]

            for i in range(16, 64):
                s0 = self._ror(w[i - 15], 7) ^ self._ror(w[i - 15], 18) ^ (w[i - 15] >> 3)
                s1 = self._ror(w[i - 2], 17) ^ self._ror(w[i - 2], 19) ^ (w[i - 2] >> 10)
                w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF)

            a, b, c, d, e, f, g, h = self._h

            for i in range(64):
                s0 = self._ror(a, 2) ^ self._ror(a, 13) ^ self._ror(a, 22)
                maj = (a & b) ^ (a & c) ^ (b & c)
                temp2 = s0 + maj
                s1 = self._ror(e, 6) ^ self._ror(e, 11) ^ self._ror(e, 25)
                ch = (e & f) ^ ((~e) & g)
                temp1 = h + s1 + ch + self._k[i] + w[i]

                h = g
                g = f
                f = e
                e = (d + temp1) & 0xFFFFFFFF  # 32-bit modular add
                d = c
                c = b
                b = a
                a = (temp1 + temp2) & 0xFFFFFFFF  # 32-bit modular add

            self._h = [(x + y) & 0xFFFFFFFF for x, y in zip(self._h, [a, b, c, d, e, f, g, h])]

        return self._digest()

    def _digest(self):
        digest = (self._h[0] << 224) | (self._h[1] << 192) | (self._h[2] << 160) | \
                 (self._h[3] << 128) | (self._h[4] << 96) | (self._h[5] << 64) | \
                 (self._h[6] << 32) | self._h[7]
        return hex(digest)[2:].zfill(64)

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

    def _ror(self, data, amount):
        """
        32-bit rotate right command.

        :param data: Data to rotate.
        :param amount: Amount to rotate.
        :return: Rotated data.
        """
        return ((data >> amount) | (data << (32 - amount))) & 0xFFFFFFFF
