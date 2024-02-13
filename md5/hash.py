class MD5(object):
    def __init__(self, data=None):
        """
        Class to hash data using MD5

        :param data: Data to hash.
        """
        self.DESIRED_BYTE_LENGTH = 8

        self._k = [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf,
                   0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
                   0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e,
                   0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                   0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6,
                   0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
                   0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
                   0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                   0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039,
                   0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
                   0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d,
                   0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                   0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391]

        self._A0 = 0x67452301
        self._B0 = 0xEFCDAB89
        self._C0 = 0x98BADCFE
        self._D0 = 0x10325476
        self._s = [(7, 12, 17, 22), (5, 9, 14, 20), (4, 11, 16, 23), (6, 10, 15, 21)]
        # duplicate each value 4 times, unpack tuple values to list, then combine the lists
        # (sum with empty list will "open up" all the lists to combine them)
        self._s = sum([[*vals * 4] for vals in self._s], [])

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
            # convert to bytearray
            if isinstance(value, str):
                self._data = bytearray(value, 'utf-8')
            else:
                self._data = bytearray(value)

    def hash(self, data=None):
        """
        Hash data using the MD5 hash function.

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
        self.data += bit_len.to_bytes(8, byteorder="little")

        # functions to calculate values for hash
        f1 = lambda b, c, d: (b & c) | (~b & d)
        f2 = lambda b, c, d: (d & b) | (~d & c)
        f3 = lambda b, c, d: b ^ c ^ d
        f4 = lambda b, c, d: c ^ (b | ~d)

        g1 = lambda i: i
        g2 = lambda i: (5 * i + 1) % 16
        g3 = lambda i: (3 * i + 5) % 16
        g4 = lambda i: (7 * i) % 16

        # split to 512-bit blocks
        for block in self._nsplit(self._data, 64):
            a = self._A0
            b = self._B0
            c = self._C0
            d = self._D0

            for i in range(64):
                f, g = 0, 0
                if i < 16:
                    f = f1(b, c, d)
                    g = g1(i)
                elif i < 32:
                    f = f2(b, c, d)
                    g = g2(i)
                elif i < 48:
                    f = f3(b, c, d)
                    g = g3(i)
                elif i < 64:
                    f = f4(b, c, d)
                    g = g4(i)
                # convert to "int"
                f = a + f + self._k[i] + int.from_bytes(block[4 * g:4 * g + 4], byteorder='little')
                new_b = (b + self._rol(f, self._s[i])) & 0xFFFFFFFF
                a, b, c, d = d, new_b, b, c

            # modular add with 32-bits (python has no overflow)
            self._A0 += a
            self._A0 &= 0xFFFFFFFF
            self._B0 += b
            self._B0 &= 0xFFFFFFFF
            self._C0 += c
            self._C0 &= 0xFFFFFFFF
            self._D0 += d
            self._D0 &= 0xFFFFFFFF

        values = (self._A0, self._B0, self._C0, self._D0)
        hashed = sum(val << (32 * i) for i, val in enumerate(values))  # shifting then or-ing basically
        # convert to bytes, switch from little endian back to big endian, then return as hex string
        return hex(int.from_bytes(hashed.to_bytes(16, byteorder='little'), byteorder="big"))[2:].zfill(32)

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
        data &= 0xFFFFFFFF
        return ((data << amount) | (data >> (32 - amount))) & 0xFFFFFFFF
