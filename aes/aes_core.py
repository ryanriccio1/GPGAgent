# Author:   Ryan Riccio
# Program:  AES Core Functions
# Date:     November 17th, 2022
from aes.aes_constants import AESConstants


class AESCore(AESConstants):
    def _encrypt_block(self, pt_block):
        """
        Encrypt block using AES.

        :param bytes pt_block: 128-bit block of plaintext.
        :return: ct_block
        :rtype: bytes
        """
        pt_block = self._bytes_to_table(pt_block)

        # follow algorithm from AES wiki
        self._add_round_key(pt_block, self._keys[0])

        for i in range(1, self._rounds):
            self._sub_bytes(pt_block, self._enc_s_box)
            self._shift_rows(pt_block)
            self._mix_cols(pt_block)
            self._add_round_key(pt_block, self._keys[i])

        self._sub_bytes(pt_block, self._enc_s_box)
        self._shift_rows(pt_block)
        self._add_round_key(pt_block, self._keys[-1])

        ct_block = self._table_to_bytes(pt_block)
        return ct_block

    def _decrypt_block(self, ct_block):
        """
        Decrypt block using AES.

        :param bytes ct_block: 128-bit block of ciphertext.
        :return: pt_block
        :rtype: bytes
        """
        ct_block = self._bytes_to_table(ct_block)

        # follow algorithm from AES wiki
        self._add_round_key(ct_block, self._keys[-1])
        self._unshift_rows(ct_block)
        self._sub_bytes(ct_block, self._dec_s_box)

        for i in range(self._rounds - 1, 0, -1):
            self._add_round_key(ct_block, self._keys[i])
            self._unmix_cols(ct_block)
            self._unshift_rows(ct_block)
            self._sub_bytes(ct_block, self._dec_s_box)

        self._add_round_key(ct_block, self._keys[0])

        pt_block = self._table_to_bytes(ct_block)
        return pt_block

    # https://en.wikipedia.org/wiki/AES_key_schedule
    # https://www.brainkart.com/article/AES-Key-Expansion_8410/
    def _generate_keys(self, key):
        """
        Generate key table from master key.

        :param bytes key: Key to use to generate table.
        :return: Key table that is 4 col wide, x rows long where x is the length of the master key in 32-bit words.
        :rtype: list[list[bytes]]
        """
        # use key to start key table
        key_table = self._bytes_to_table(key)
        # (32-bit) 4 words for AES-128, 6 words for AES-192, and 8 words for AES-256
        word_size = len(key) // 4

        current_round = 1
        # we go through 4 iterations per (round + 1). 128-bit has 10 rounds, so 44 iterations
        while len(key_table) < (self._rounds + 1) * 4:
            # get the last word
            word = list(key_table[-1])
            # if i >= N and i % N == 0, SubWord(RotWord(Wi-1))^rcon from wiki
            if len(key_table) % word_size == 0:
                # left circular shift (RotWord)
                word.append(word.pop(0))

                # perform s-box substitution on word (SubWord)
                word = [self._enc_s_box[b] for b in word]

                # xor with round constant based on round (^rcon)
                word[0] ^= self._round_constants[current_round]

                # increment round
                current_round += 1

            # if i >= N, N > 6 and i % N == 4, SubWord(Wi-1)
            # this only occurs for 256-bit encryption (N > 6)
            elif len(key) == 32 and len(key_table) % word_size == 4:
                # perform s-box substitution
                word = [self._enc_s_box[b] for b in word]

            # Wi-N ^ Wi-1
            # xor with last word in same position
            word = self._xor(word, key_table[-word_size])
            key_table.append(word)
        # convert keys into 4 x X table (11 tables for AES-128, 13 for AES-192, 15 for 256)
        return [key_table[4 * i: 4 * (i + 1)] for i in range(len(key_table) // 4)]

    @staticmethod
    def _sub_bytes(block, table):
        """
        Perform S-BOX substitutions using a give s-box table.

        :param list[list[int]] block: Block to perform substitutions on.
        :param list[int] table: table to use for substitution.
        :return: Mutates original block.
        :rtype: None
        """
        for row in range(4):
            for col in range(4):
                block[row][col] = table[block[row][col]]

    @staticmethod
    def _shift_rows(block):
        """
        Shift blocks in given table.

        :param list[list[bytes]] block: Block to perform shift on.
        :return: Mutates original block.
        :rtype: None
        """
        block[0][1], block[1][1], block[2][1], block[3][1] = block[1][1], block[2][1], block[3][1], block[0][1]
        block[0][2], block[1][2], block[2][2], block[3][2] = block[2][2], block[3][2], block[0][2], block[1][2]
        block[0][3], block[1][3], block[2][3], block[3][3] = block[3][3], block[0][3], block[1][3], block[2][3]

    @staticmethod
    def _unshift_rows(block):
        """
        Un-shifts blocks in given table.

        :param list[list[bytes]] block: Block to perform shift on.
        :return: Mutates original block.
        :rtype: None
        """
        block[0][1], block[1][1], block[2][1], block[3][1] = block[3][1], block[0][1], block[1][1], block[2][1]
        block[0][2], block[1][2], block[2][2], block[3][2] = block[2][2], block[3][2], block[0][2], block[1][2]
        block[0][3], block[1][3], block[2][3], block[3][3] = block[1][3], block[2][3], block[3][3], block[0][3]

    @staticmethod
    def _add_round_key(block, key):
        for row in range(4):
            for col in range(4):
                block[row][col] ^= key[row][col]

    # https://en.wikipedia.org/wiki/Advanced_Encryption_Standard#Description_of_the_ciphers
    # https://en.wikipedia.org/wiki/Rijndael_MixColumns
    # https://web.archive.org/web/20100626212235/http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
    # https://cs.ru.nl/~joan/papers/JDA_VRI_Rijndael_2002.pdf
    @staticmethod
    def _x_time(col):
        """
        Fast method of performing calculations for Rijndael column substitution.

        :param int col: Column to shift.
        :return: Shifted column.
        :rtype: int
        """
        return (((col << 1) ^ 0x1B) & 0xFF) if (col & 0x80) else (col << 1)

    def _mix_col(self, col):
        """
        Mix an individual column.

        :param list[int] col: Column to mix.
        :return: Performs mutation on original column.
        :rtype: None
        """
        e = col[0] ^ col[1] ^ col[2] ^ col[3]
        orig_entry = col[0]
        col[0] ^= e ^ self._x_time(col[0] ^ col[1])
        col[1] ^= e ^ self._x_time(col[1] ^ col[2])
        col[2] ^= e ^ self._x_time(col[2] ^ col[3])
        col[3] ^= e ^ self._x_time(col[3] ^ orig_entry)

    def _mix_cols(self, block):
        """
        Mix all columns in 4x4 table.

        :param list[list[int]] block: Block to perform mixing on.
        :return: Mutates original block.
        :rtype: None
        """
        for row in range(4):
            self._mix_col(block[row])

    def _unmix_cols(self, block):
        """
        Performs inverse operation of _mix_cols

        :param list[list[int]] block: Block to unmix.
        :return: Mutates original block.
        :rtype: None
        """
        for row in range(4):
            u = self._x_time(self._x_time(block[row][0] ^ block[row][2]))
            v = self._x_time(self._x_time(block[row][1] ^ block[row][3]))
            block[row][0] ^= u
            block[row][1] ^= v
            block[row][2] ^= u
            block[row][3] ^= v

        self._mix_cols(block)

    @staticmethod
    def _bytes_to_table(data):
        """
        Convert bytes to table with dimensions rows: len(data) // 4 x cols: 4.

        :param bytes data: Bytes to convert to table.
        :return: Bytes as table.
        :rtype: list[list[bytes]]
        """
        return [list(data[i:i + 4]) for i in range(0, len(data), 4)]

    @staticmethod
    def _table_to_bytes(table):
        """
        Convert table back to bytes.

        :param list[list[bytes]] table: Table to convert to bytes.
        :return: Table as bytes.
        :rtype: bytes
        """
        return bytes(sum(table, []))

    @staticmethod
    def _xor(x, y):
        """
        Bitwise XOR of two items. Converts to bytes after.

        :param x: First item to XOR.
        :param y: Second item to XOR.
        :return: XORed bytes.
        :rtype: bytes
        """
        return bytes(x[idx] ^ y[idx] for idx in range(min(len(x), len(y))))

    @staticmethod
    def _add_padding(data):
        """
        Add PKCS#7 padding to data (assuming data is multiple of 8 bits).

        :param data: Data to pad.
        :return: Padded data.
        """
        return data + bytes([16 - len(data) % 16] *
                            (16 - len(data) % 16))

    @staticmethod
    def _rem_padding(data):
        """
        Remove PKCS#7 padding from data.

        :param data: Data to remove padding from
        :return: Un-padded data.
        """
        return data[:len(data) - data[-1]]

    @staticmethod
    def _nsplit(data, split_size=64):
        """
        Split data into 'split_size' chunks.

        :param bytes data: Data to split.
        :param split_size: Size for each block.
        :return: Iterator which gives data block.
        :rtype: generator
        """
        for idx in range(0, len(data), split_size):
            yield data[idx:idx + split_size]

    @staticmethod
    def _bytes_to_bit_array(byte_string):
        """
        Convert bytestring to array of bits.

        :param bytes byte_string: bytestring to convert to bits
        :return: array of bits
        :rtype: list
        """
        # convert bytestring to ints, ints to binary, fill leading zeros, convert each string to int and return
        bits = bin(int.from_bytes(byte_string, byteorder="big"))[2:].zfill(len(byte_string) * 8)
        return [int(bit) for bit in bits]

