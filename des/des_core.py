# Author:   Ryan Riccio
# Program:  DES Core Functions
# Date:     November 17th, 2022
from des.des_constants import *


class DESCore(DESConstants):
    def _add_padding(self, message):
        """
        Add padding to the end of each bytestring. The value of the padding is equal to the length of the padding.

        :param bytes message: bytestring message to add padding to
        :return: bytestring of the padded message
        :rtype: bytes
        """
        return message + bytes([self.DESIRED_BYTE_LENGTH - len(message) % self.DESIRED_BYTE_LENGTH] *
                               (self.DESIRED_BYTE_LENGTH - len(message) % self.DESIRED_BYTE_LENGTH))

    def _rem_padding(self, message):
        """
         Remove padding from the end of each bytestring. The amount to remove is specified by the padding value.

        :param bytes message: bytestring message to remove padding from
        :return: bytestring of the message
        :rtype: bytes
        """
        return message[:len(message) - message[-1]]

    def _bytes_to_bit_array(self, byte_string):
        """
        Convert bytestring to array of bits.

        :param bytes byte_string: bytestring to convert to bits
        :return: array of bits
        :rtype: list
        """
        # convert bytestring to ints, ints to binary, fill leading zeros, convert each string to int and return
        bits = bin(int.from_bytes(byte_string, byteorder="big"))[2:].zfill(len(byte_string) * self.DESIRED_BYTE_LENGTH)
        return [int(bit) for bit in bits]

    def _bit_array_to_bytes(self, bit_array):
        """
        Convert arrray of bits to bytestring.

        :param list bit_array: bit array to convert to bytestring
        :return: bytestring from bit array
        :rtype: bytes
        """
        # convert each bit to string, then join the string to 8-bit sections, convert 8-bit sections to int base 2,
        # convert ints to bytes and return bytestring
        bit_array = [str(bit) for bit in bit_array]
        bit_array = ["".join(bit_array[pos:pos + self.DESIRED_BYTE_LENGTH]) for pos in
                     range(0, len(bit_array), self.DESIRED_BYTE_LENGTH)]
        return bytes([int(byte, 2) for byte in bit_array])

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

    def _lshift(self, sequence, n):
        """
        Shifts sequence of bytes left n times.

        :param list sequence: sequence to shift
        :param int n: amount to shift by
        :return: shifted list
        :rtype: list
        """
        return sequence[n:] + sequence[:n]

    def _xor(self, x, y):
        """
        XOR two iterables together (if lengths are different, only XOR where they overlap).

        :param iterable x: first list of values
        :param iterable y: second list of values
        :return: list of XORed values
        :rtype: list
        """
        return [x[idx] ^ y[idx] for idx in range(min(len(x), len(y)))]

    def _permute(self, block, table):
        """
        Shuffle a block of bits based on a permutation table.

        :param list block: list of bits to shuffle
        :param list table: permutation table to use
        :return: list of shuffled bits
        :rtype: list
        """
        return [block[x] for x in table]

    def _substitute(self, block):
        """
        Perform DES SBOX substitutions

        :param list block: 48 bits of input
        :return: list of 32 bits of data
        """
        # convert everything to string (int() requires string)
        block = [str(item) for item in block]
        smaller_block = []

        # loop through each 6 bit sections
        for idx, current_block in enumerate(self._nsplit(block, split_size=6)):
            # convert bits to int to get rows and columns
            row = int("".join(current_block[0] + current_block[-1]), 2)
            col = int("".join(current_block[1:-1]), 2)
            # get substitution and add each bit to list and convert back to int
            bits = bin(self._S_BOXES[idx][row][col])[2:].zfill(4)
            for ch in bits:
                smaller_block.append(int(ch))

        return smaller_block

    def _generate_sub_keys(self, encryption_key):
        """
        Generates 16 DES sub-keys from a 64-bit encryption key. The encryption
        key should be given as a bytes string. Output is a 16-element list of
        bit arrays, where each array is a list of 48 ones/zeroes.

        :param bytes encryption_key: 64-bit bytestring to use for key.
        :return: 16 48-bit DES sub-keys.
        :rtype: list[list[int]]
        """
        sub_keys = []
        key_bits = self._bytes_to_bit_array(encryption_key)
        k_0 = self._permute(key_bits, self._KEY_PERMUTATION1)  # 56-bit key

        # split into 2 28-bit parts
        right = k_0[28:]
        left = k_0[:28]
        for i in range(16):
            # shift based on shift table
            left = self._lshift(left, self._KEY_SHIFT[i])
            right = self._lshift(right, self._KEY_SHIFT[i])
            # permute and add
            k_i = self._permute(left + right, self._KEY_PERMUTATION2)
            sub_keys.append(k_i)
        return sub_keys

    def _function(self, right_side, key):
        """
        Performs the DES encryption "function" on the 32-bit Right Side of a
        64-bit block. This operation is invoked 16 times for each block, each
        time with a different subkey.

        :param list[int] right_side: 32-bits of the right side of the block.
        :param list[int] key: 48-bit sub-key.
        :return: 32-bit processed right side.
        :rtype: list[int]
        """
        right_side = self._permute(right_side, self._EXPAND)  # 48-bits
        block = self._xor(right_side, key)  # 48-bits
        block = self._substitute(block)  # 32-bits
        block = self._permute(block, self._S_BOX_PERMUTATION)  # post S-BOX permutation
        return block  # 32-bits

    def _crypt_block(self, block, sub_keys):
        """
        Encrypt a block of bits for DES.

        :param list[int] block: 64-bit block to encrypt
        :param list[list[int]] sub_keys: 16 48-bit sub-keys.
        :return: list of encrypted bits
        :rtype: list[int]
        """
        block = self._permute(block, self._INIT_PERMUTATION)
        for i in range(16):
            # split each side
            left = block[:32]
            right = block[32:]

            # make sure to copy list to make sure we're not just renaming it
            new_left = right.copy()
            new_right = self._xor(self._function(right, sub_keys[i]), left)
            block = new_left + new_right

        # swap the side one more time before final permutation
        return self._permute(block[32:] + block[:32], self._FINAL_PERMUTATION)