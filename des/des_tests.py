# Author:   Ryan Riccio
# Program:  DES Main Tests
# Date:     November 17th, 2022
import des


class DESTest(des.TDES):
    def run_unit_tests(self):
        """
        Run tests of DES functions
        """
        # region PAD
        pad_test_in1 = b'CSC428'
        pad_test_out1 = b'CSC428\x02\x02'

        pad_test_in2 = b'TALLMAN'
        pad_test_out2 = b'TALLMAN\x01'

        pad_test_in3 = b'JTALLMAN'
        pad_test_out3 = b'JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08'

        assert self._add_padding(pad_test_in1) == pad_test_out1, f"Unit test #1 failed: _add_padding({pad_test_in1})"
        assert self._add_padding(pad_test_in2) == pad_test_out2, f"Unit test #2 failed: _add_padding({pad_test_in2})"
        assert self._add_padding(pad_test_in3) == pad_test_out3, f"Unit test #3 failed: _add_padding({pad_test_in3})"

        assert self._rem_padding(pad_test_out1) == pad_test_in1, f"Unit test #4 failed: _rem_padding({pad_test_out1})"
        assert self._rem_padding(pad_test_out2) == pad_test_in2, f"Unit test #5 failed: _rem_padding({pad_test_out2})"
        assert self._rem_padding(pad_test_out3) == pad_test_in3, f"Unit test #6 failed: _rem_padding({pad_test_out3})"
        # endregion
        # region BTB
        btb_test_in1 = b'\x00'
        btb_test_out1 = [0, 0, 0, 0, 0, 0, 0, 0]

        btb_test_in2 = b'\xA5'
        btb_test_out2 = [1, 0, 1, 0, 0, 1, 0, 1]

        btb_test_in3 = b'\xFF'
        btb_test_out3 = [1, 1, 1, 1, 1, 1, 1, 1]

        assert self._bytes_to_bit_array(btb_test_in1) == btb_test_out1, \
            f"Unit test #7 failed: _bytes_to_bit_array({btb_test_in1})"
        assert self._bytes_to_bit_array(btb_test_in2) == btb_test_out2, \
            f"Unit test #8 failed: _bytes_to_bit_array({btb_test_in2})"
        assert self._bytes_to_bit_array(btb_test_in3) == btb_test_out3, \
            f"Unit test #9 failed: _bytes_to_bit_array({btb_test_in3})"

        assert self._bit_array_to_bytes(btb_test_out1) == btb_test_in1, \
            f"Unit test #10 failed: _bit_array_to__bytes({btb_test_out1})"
        assert self._bit_array_to_bytes(btb_test_out2) == btb_test_in2, \
            f"Unit test #11 failed: _bit_array_to__bytes({btb_test_out2})"
        assert self._bit_array_to_bytes(btb_test_out3) == btb_test_in3, \
            f"Unit test #12 failed: _bit_array_to__bytes({btb_test_out3})"
        # endregion
        # region NSPLIT
        nsplit_in1 = b"1111222233334444"
        nsplit_sz1 = 4
        nsplit_out1 = [b'1111', b'2222', b'3333', b'4444']
        nsplit_test1 = self._nsplit(nsplit_in1, nsplit_sz1)
        nsplit_join1 = [item for item in nsplit_test1]

        nsplit_in2 = b"ABCDEFGHIJKLMN"
        nsplit_sz2 = 3
        nsplit_out2 = [b'ABC', b'DEF', b'GHI', b'JKL', b'MN']
        nsplit_test2 = self._nsplit(nsplit_in2, nsplit_sz2)
        nsplit_join2 = [item for item in nsplit_test2]

        nsplit_in3 = b"THE CODE BOOK BY SINGH"
        nsplit_sz3 = 5
        nsplit_out3 = [b'THE C', b'ODE B', b'OOK B', b'Y SIN', b'GH']
        nsplit_test3 = self._nsplit(nsplit_in3, nsplit_sz3)
        nsplit_join3 = [item for item in nsplit_test3]

        assert nsplit_join1 == nsplit_out1, f"Unit test #13 failed: _nsplit({nsplit_in1})"
        assert nsplit_join2 == nsplit_out2, f"Unit test #14 failed: _nsplit({nsplit_in2})"
        assert nsplit_join3 == nsplit_out3, f"Unit test #15 failed: _nsplit({nsplit_in2})"
        # endregion
        # region XOR
        xor_test_inx1 = [0, 0, 0, 0, 0, 0, 0, 0]
        xor_test_iny1 = [1, 1, 1, 1, 1, 1, 1, 1]
        xor_test_out1 = [1, 1, 1, 1, 1, 1, 1, 1]

        xor_test_inx2 = [1, 0, 1, 0, 0, 0, 0, 0]
        xor_test_iny2 = [0, 1, 0, 1, 0, 1, 0, 1]
        xor_test_out2 = [1, 1, 1, 1, 0, 1, 0, 1]

        xor_test_inx3 = [1, 1, 1, 1, 1, 1, 0, 0]
        xor_test_iny3 = [1, 1, 1, 1, 1, 1, 1, 1]
        xor_test_out3 = [0, 0, 0, 0, 0, 0, 1, 1]

        assert self._xor(xor_test_inx1, xor_test_iny1) == xor_test_out1, \
            f"Unit test #16 failed: _xor({xor_test_inx1}, {xor_test_iny1})"
        assert self._xor(xor_test_inx2, xor_test_iny2) == xor_test_out2, \
            f"Unit test #17 failed: _xor({xor_test_inx2}, {xor_test_iny2})"
        assert self._xor(xor_test_inx3, xor_test_iny3) == xor_test_out3, \
            f"Unit test #18 failed: _xor({xor_test_inx3}, {xor_test_iny3})"
        # endregion
        # region LSHIFT
        ls_test_in1 = ['a', 'b', 'c', 'd', 'e', 'f']
        ls_test_ns1 = 3
        ls_test_ou1 = ['d', 'e', 'f', 'a', 'b', 'c']

        ls_test_in2 = [1, 0, 1, 0, 1, 0, 1, 0]
        ls_test_ns2 = 1
        ls_test_ou2 = [0, 1, 0, 1, 0, 1, 0, 1]

        assert self._lshift(ls_test_in1, ls_test_ns1) == ls_test_ou1, \
            f"Unit test #19 failed: _lshift({ls_test_in1}, {ls_test_ns1})"
        assert self._lshift(ls_test_in2, ls_test_ns2) == ls_test_ou2, \
            f"Unit test #20 failed: _lshift({ls_test_in2}, {ls_test_ns2})"
        # endregion
        # region PERMUTE
        perm_test_in = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
                        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
                        32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
                        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]

        perm_test_out1 = self._INIT_PERMUTATION
        perm_test_out2 = self._FINAL_PERMUTATION
        perm_test_out3 = self._EXPAND
        perm_test_out4 = self._S_BOX_PERMUTATION

        assert self._permute(perm_test_in, self._INIT_PERMUTATION) == perm_test_out1, \
            f"Unit test #21 failed: _permute({perm_test_in[:10]}, _INIT_PERMUTATION)"
        assert self._permute(perm_test_in, self._FINAL_PERMUTATION) == perm_test_out2, \
            f"Unit test #22 failed: _permute({perm_test_in[:10]}, _FINAL_PERMUTATION)"
        assert self._permute(perm_test_in, self._EXPAND) == perm_test_out3, \
            f"Unit test #23 failed: _permute({perm_test_in[:10]}, _EXPAND)"
        assert self._permute(perm_test_in, self._S_BOX_PERMUTATION) == perm_test_out4, \
            f"Unit test #24 failed: _permute({perm_test_in[:10]}, _CONTRACT)"
        # endregion
        # region SBOX
        sbox_test_in = [1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0,
                        1,
                        1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1]
        sbox_test_out = [1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0]

        assert self._substitute(sbox_test_in) == sbox_test_out, f"Unit test #25 failed: _substitute({sbox_test_in[:10]}...)"
        # endregion
        # region SUB-KEY
        subkey_test_in = b"\xEF\x00\xEF\x00\xFF\x80\xFF\x80"
        subkey_test_out = [[0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1,
                            1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0],
                           [1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1,
                            0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1],
                           [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1,
                            0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1],
                           [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                            0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1],
                           [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                            0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1],
                           [1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                            0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1],
                           [1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                            0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1],
                           [1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                            0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1],
                           [1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0,
                            0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                           [1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0,
                            1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                           [0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0,
                            1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                           [0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0,
                            1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                           [0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0,
                            1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0],
                           [0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0,
                            1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                           [0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 1,
                            1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0],
                           [1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1,
                            0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1]]

        assert self._generate_sub_keys(subkey_test_in) == subkey_test_out, \
            f"Unit test #26 failed: _generate_sub_keys({subkey_test_in})"
        # endregion
        # region FUNC
        func_test_right_in = [1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1,
                              0,
                              1]
        func_test_key_in = [1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 0, 1, 1,
                            0,
                            0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1]
        func_test_out = [1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0]

        assert self._function(func_test_right_in, func_test_key_in) == func_test_out, \
            f"Unit test #27 failed: _function({func_test_right_in[:10]}..., {func_test_key_in[:10]}...)"
        # endregion

        print("ALL UNIT TESTS PASS")

    def run_system_test(self):
        # region SINGLE DES
        self.key = b'\x01\x02\x03\x04\x05\x06\x07\x08'
        self.iv = b'\x00\x00\x00\x00\x00\x00\x00\x00'

        # region ECB
        encrypt_ecb = self.encrypt(b'this is a test!')
        decrypt_ecb = self.decrypt(encrypt_ecb)

        assert self.as_hex(encrypt_ecb) == "c61d5489ea1cc84a1b18279680f57777", "Encrypt ECB Test Failed."
        assert decrypt_ecb == b'this is a test!', "Decrypt ECB Test Failed."
        # endregion
        # region CBC
        self.mode = des.DESMode.CBC

        encrypt_cbc = self.encrypt(b'this is a test!')
        self.reset()
        decrypt_cbc = self.decrypt(encrypt_cbc)
        self.reset()

        assert self.as_hex(encrypt_cbc) == "c61d5489ea1cc84a1997dbda94b975dc", "Encrypt CBC Failed."
        assert decrypt_cbc == b'this is a test!', "Decrypt CBC Test Failed."
        # endregion
        # region OFB
        self.mode = des.DESMode.OFB

        encrypt_ofb = self.encrypt(b'this is a test!')
        self.reset()
        decrypt_ofb = self.decrypt(encrypt_ofb)
        self.reset()

        assert self.as_hex(encrypt_ofb) == "c41bb54c9260204de53b958ead4f0b", "Encrypt OFB Failed."
        assert decrypt_ofb == b'this is a test!', "Decrypt OFB Test Failed."
        # endregion
        print("SINGLE DES SYSTEM TEST PASS")
        # endregion

        # region TRIPLE DES
        self.key = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x20\x21\x22\x23\x24'
        self.iv = b'\x00\x00\x00\x00\x00\x00\x00\x00'

        # region ECB
        self.mode = des.DESMode.ECB

        encrypt_ecb = self.encrypt(b'this is a test!')
        decrypt_ecb = self.decrypt(encrypt_ecb)

        assert self.as_hex(encrypt_ecb) == "1eb7c196c593c44bf13dbc8f66010044", "Encrypt ECB Test Failed."
        assert decrypt_ecb == b'this is a test!', "Decrypt ECB Test Failed."
        # endregion
        # region CBC
        self.mode = des.DESMode.CBC

        encrypt_cbc = self.encrypt(b'this is a test!')
        self.reset()
        decrypt_cbc = self.decrypt(encrypt_cbc)
        self.reset()

        assert self.as_hex(encrypt_cbc) == "1eb7c196c593c44b4ecbb0a82e053db1", "Encrypt CBC Failed."
        assert decrypt_cbc == b'this is a test!', "Decrypt CBC Test Failed."
        # endregion
        # region OFB
        self.mode = des.DESMode.OFB

        encrypt_ofb = self.encrypt(b'this is a test!')
        self.reset()
        decrypt_ofb = self.decrypt(encrypt_ofb)
        self.reset()

        assert self.as_hex(encrypt_ofb) == "d7fbe4e5d8f3628ab35202b2b77d68", "Encrypt OFB Failed."
        assert decrypt_ofb == b'this is a test!', "Decrypt OFB Test Failed."
        # endregion
        print("TRIPLE DES SYSTEM TEST PASS")
        # endregion


if __name__ == '__main__':
    tester = DESTest()
    tester.run_unit_tests()
    tester.run_system_test()

    # tdes = des.TDES()
    #
    # tdes.key = b'\xde\xad\xbe\xef\x7a\xc0\xba\xbe\xca\xfe\xf0\x0d\xca\x7d\x00\xd1\x23\x45\x67\x89\x0a\xbc\xde\xf9'
    # ciphertext1 = b'.<\xef\xec\x03\x9d\xc6>\x03U\xde\xdc\xfe,f\xbe\xef\xe3\x15\x13\x8e+m\xb1D,\x10\x89\xf5g\xcaCh\x88.\xd3\xe3\xcf\xfb\xd1\x87\xc22U\xe4\x07\x02\x17\xe6)!\x06\x8c\xeeu\xc1\xc7\xa5!Yb\xe3!\xe7\x02\xeb\xd2h\x97/\x8aUf7\x12i\x1ez\x07\x82\xf2M\xcf\xf0&\xc9O\xf49:0\xfdv\x0cT.D\xddc\xfe\xd8t\x8b\xf4\xa1oq0G}\r\xb4b\x1c\x9a\xad\x98\xfe\xad\x8a\x1f)\x88g\x9d\xb4\xed\x01H\x05\x9c^\xd5\x84G\xb6\xa6N\xbeo\xdd\xa9:\xf3\x9e\x16\x9b\xd5S\xdc6\xed"\x08\x8eK3\x82\xe2\x04\xd8*\x96X$\xaf\xdc\xa7>\x9f\'\xef\x88\xba\xca\x9b\x9cMn+\x91~W\xde\xcfx\x811^<\x8aS,\x01f\t\x87j4\xb1?\xef\x99\xa0\x98\x0cS\xe5\xb7\xcb\x1e\xb3\x0b\x10\x86L\xa2\x02\x83\x830\xb1\x17\xd6W\xbeB\x0f\x8e9 "Z\xad\xa3\xaa&\x98^\x1d\x01mn\xa1<\xb0\xab\xf8[\x06\xd6\x17\x94\xd7\xbdk\x98\xb8\xfc\xa56\t\x10\xb0\xba\x9f3\xe5\xe9\x8a\x98,-\x08`\xa8Q}\xcd\x99\x99\xea\xaa\xb8\xfa\x82\xda\xca\x9c_\x9ag\xee\xdf\x03\xcc\x19d$S\xc2\xbcsj\x99h\xcd2\xb4JpA\xa6\x1b\xce\xa1\xd2\xe6\xc1\x82\xd9ux{\xa5\xa8\xae\xdb\xc7\xf2\xa1\x027\xbbg\xf7\xfc\xd7\x08\x9c+Ks\xf9\x16\xf9/\xd2\x94"\x99\xee\xd52<\x9a\xec\x7f%\xef\xce\xbbu\x05\x88\x9f\x087\xe8\xd3(~6\na-\xa0\xa4{\x83\xaeza^3\xd8m`\x9bl\xc3\xc1\xbdZ\x9e\xf5\xab0\xef*\xdd:\xb2|u\n\xf1K\xac\xdc>c\x1c\x9e:\rfnP-\x08\xdd\x96\x9e\x7f^ \x90\xb7\x16+\x96\x1f\xca\xc4\x98\xa8h\xf0r\n\x0brn\xf5Qa\x06\xb23\xa0i]\xd8\xed\xbd\xe0\xda\xb3Zx\x97fh\x83\xd1\'d\xe4\x99\xa6\x94\xb6L*\x0c;\x8b\xadj]I\x81\x1e1\x99\x15\xff\xd0\xc4\xa9\xac\x08M\xe1)\x06\xebV\x89q\x84\xa5\x88F\x12\x95\xa0e7\xb3\xbc|L\xf7\x01\xf3\x9f\xa02z\xcf\xca\xa9\xbd\xccQ\xb6\xba\x95\xb3\xfb\x8dO!W'
    #
    # print(tdes.decrypt(ciphertext1))
    #
    # # CBC - Cipher Block Chaining
    # tdes.key = b'\xde\xad\xbe\xef\x7a\xc0\xba\xbe\xca\xfe\xf0\x0d\xca\x7d\x00\xd1\x23\x45\x67\x89\x0a\xbc\xde\xf9'
    # tdes.iv = b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
    # tdes.mode = des.DESMode.CBC
    # ciphertext2 = b'\x9e\x8f\xe5G~\xd3\xeb\x9c\xd5\xe8\xb8\x1a\x17\xe5\xa1H\xebVX\xbe\xcf}W\xc8\xb5\xa6\xfb\xbd\x1fG\x8b\x13.\x1c*\x1d\t\xab\x1c\x8d\xf3#\xf8\x86\xf4\xbad\x18\x9fR\xad\xc7\xdd\xe5\xde\xf7\xd9\xca_\x1eY\xe4\x06-s\x86\x01\x0e\xdad\x15Z\x08\x92=6\x9f\xbc\x85\x8b\xfe\xd1\x9a/W 0\x16\xa1\x07\x04\x9dY\x8c\x85Z\xeb\x11r\xa3\xff\xb1\xbbd\xd9\xb8\xa7\x1d\x88\xdc;\xfb\x8d\xde\x04\x17\xb8\xde\xd5\xce*a\x93bQ`~\x17R\xec\xb928\x9f\x9d\xe4\xaa\x08.\xe9\xfdV\xf0\xa0\xa7`\xa1\xff^\x7f\xed,/El\xab%\x85\x91\xc3\xe2s\\\x96H\xc3\xceh\x8c\x91\x87\n\xa2u\x1b.@B!\xfbg71~)P\xa5\x9f\xd3R\xdb\xa1\xb33\xe7\xbc\xbc\xf2\x9d\xbf\x08\x99\xa3\xaf\xba\x16\x0eEh\xeb(/\x8cF`K\xe7\xaav\xe1\x9d\xc1\x98\xff\xf5r)e\x06\xa1\xa1\xef\x83W\xf9\xf3\t\xc4\x14p_:\xcc]\xca,\x11y\xdbf\xae\x9f\x7f\xb1Z\x95\\\xe3\xd4\x83A\xce\xc9\xe5\x97\x82pHv\x8d\x81\xcc\x9el\xa9}\x85A\xf0\xaf\x01B2\xd7\xc9\xe7Eff\xb5GY\x85\xd0\x01\xd2\xc9\x88N\x93\x86\x9a\xab\\T\xc2\xb9\xf6\\\\H\xed\xb0\xb5\xf8\x1azW\xc2K\x12\xfe\xc1\xd4\x86\x8c\xc9\xa6IU\x0c\xc4\xfa:\xd9c\x0c\xf4\x06\xf2Kg\x82D\x15\xc1_bG\x97\xbe\x9ed\xe8\x88\x87IS\xc1\xa6\x12\xb5\xa5\xe1.\xc5T\x191\n\xca\xa5\xfb\xe0\x92L`MG\xbd\xfa9\r\x7f\xb7U$^<\x1fx\xd3\xf6\xaa\xfaK\xbe\x81\xa6\x0e\xe5\x15#L\xfa\x1c\xc0\xa3\x08r\xb0~\xf6Jh\xf5\xf8\xfdx 3\xd2\xed\x87\xc2\x1c\x01\xea\xe9v]Vcl`\x8a\xb5\xcf\x08\xd0z\x00\xa3/\xc6\xa0\xaei*\x8b\xae\xd3\xb7\x87\x98B\xf2\x15\x08/N$\x80\x80\x0f6\x1c\r\x05\x12#:E\xd8\xf0vG\rv\xf8X\'\xc3\xa3\xc4\xda\xab,\xac\xecT*\x83\xc9\xd2tz(t\xe0\xa3d\xeb*\xc0D\xea\xbe\xbc\x18\xa4\xc7\xa0%a\x01G\x13\xa4\xb3\x12\xff!\xc2#\xee\xb7\xd4M\xfa\x9fTG2v\x14T\xd7\r\x1fJ\x90&\x80\x0fblPtG3`\xfe|~Q\x07h\r[$\xcdT:/\x94\xca\xce\x84\xd5\xa5@\xa0\xa6\x83\xba\x1b\xdf\x13~:hr\xa5\xad\x8b\x14\xfe\x1ae\xf3\x91\xe3\xd1\xe3\x99\xc0\xe9\xb7\xab\xac\x7f3i\x18\x8a\x1a"\xee\xc0Y<G\xea\xbf6\xba}2\x9a\xca\xf2OTM\xdeUQ\x13\xf3+\xdc\xcdj8R\xbb\x8a\xad\x1a\x16F\xf4`!\xc2\xeb\x12o\xf2\xb5\xefU\xc9\x01\x85l\xfe>\x15uF\x84\x1f\r\xfc\x8a{u\tLZ\xcf\xbd\x17\xb3X\xca\xc0\xa2\xaf\xb1\xb0\xb0>\x04\xdaK\x14\xb3\x1f\xd1\xabU\xb5z\xe4Z=\xa8\xf4\xc7\x9f[\xaf\xa2w\x9e#}\x9cO\xfa\xa8\xdb%\x8am\xfb1\xc2x\xa2\x9f1G\x02b\xa4c\xc7r\xa7yr\xe1-\xbc\xdfq\xcc=\x028\xc4\r\xf1x\x8bzc\xff`h\xdf(\x8eRS\xde\x8e\xa5\xc2<n\xcf\xfe\xe0\x8e\xb1\xd8\xc3N\xe9]\x1a\xe6\xaf\xf3DB\xc2\xa4:\xad>\xbd\xc2\xb1\x89\xe5\x98\xdb]\x14\x91\xf9\xdf\xcf\x11\x1f\xc5p\rr\xe0\xf8\x19S\x9f\xee\x08\r\x02\xafF/\xc7\x9a5UPb\x1a\x9a\x13Yv\xe3\xf9\xb3\x1d\xb5\x93\xe5\\HH\xc7\xe2\xd6}\x87\xc57g\x17\xa7\xbe\x96\x80"9u\x9a\x9e\xdc\xd7\xb8\xff\x96\xab\xa9\xd0\xee\x11CzIc\x16\xd9\x98X\x14\xe7\xcb\x89k\r4\x05@\x87\xc9\xf78\xb8\x9c\xba\xad+v\xee.\xacON\x94\xc8\xf3\xb7)\xfe\xcb\x97p\r\x94\x95\xd7\n\xdf\x144\x1c>\x0f\xfd\x08]\xa2\xb4\x05\n\xb5\xea\x0b\xeb\x11\x9e\x04A\x1c;\xb6\x00\xc9\xf3\x8d9K\x12\x7fE\x98\xeb\x10MM \x95)5\x9b\x01r\x9a\x96\x17m\xb4\xf7\xadC\xa5f\xf8y\n\x0c.\xd3\xf2\x06\x14Q_\xdf\x11\x80y\x0c\n\xccuu\x87\xeb~\x9f\xc4\xde\x83\x96a\xdc\xbc\xf6N\r?,\xf7+k\xde\xc7\x04\x1fJ\xc9&\x91z\xc8\xd5M{\xa6\xad\xc9\x9d\xcfF\x89^\xe3\xb8S\xabQ\xd1\xf4\x17\xc6\xd3\x99\xf4\xe8\xab1s\xc2A\x96\xdd\xd8i\x9f\xf6>Hu\x8b\xf7 "\x8c\xdf\xc7$U;\t2\x1ce\x1c\xf9l\x1d+\xe5\x05\xd3d\x98?\xc4\x14=o\xbb \xd9\x01\xb3\xbb\xa2\xc7o\xc1<f|\x8e\xb1^\x95\xf6\x98\x03dy\x1da\x94uH\x94\xeb\x039d\xd9\x107\x13\x16\x80\x7f\xd3X\xd4\x95\x070ye\xc75\x8e*de\x06\x05U+\x1d\xdf\xf3\xf1\xb5\x06K\xf4\x7f"{ \xdd5|\xd2G*\xd2\x06\xc8\x10\xac\xed\xe2\x1f=\x06'
    #
    # print(tdes.decrypt(ciphertext2))
    #
    # # OFB - Output Feedback
    # tdes.key = b'\xde\xad\xbe\xef\x7a\xc0\xba\xbe\xca\xfe\xf0\x0d\xca\x7d\x00\xd1\x23\x45\x67\x89\x0a\xbc\xde\xf9'
    # tdes.iv = b'\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
    # tdes.mode = des.DESMode.OFB
    # ciphertext3 = b'\xaa\xa6\\6\x9f\xbb)\x1b\xb2\x14\xfb\xf2\x88\xebQ?\xa3\xaf\x8b|l\xdaG>\xd1\x84\x83l(\x18\x9a\x1cG\x11t\x9b\xf1\x9b<\r)SD \xd0\x01\x05\xc5\xdb\xed\x8e\x1a)\xbd\x8c\xfcG\xbfB\xf2\xc8%R\x04\x8a\x92{\xc1VPV\xea\x98\x1e\x0e\xfaA\xcb\xb6!\x96]wA\x98\xbe*\x86\xb3\x1a\xdc$\x85x\xe1HM\xf5Z\xcd\x10\xfc\xa6d\x17\x0f#\xb7\xdcu\xbe\x04B46\x1a69c\x10&\x0f\xb0,\x85\xb8\x04\xa7\x9f\x95\xe3\x06\xf3\x17L\xd7\xff\x8c\xee\xf42\xb7\xa9\xfcJuB7\x83\x83\x8b\x89Eq8\x80\xb4\x7fQ\xa8\xd089O\xf6\xc81j\xc3u\xb3[\xcb\xe5,P\xebqT\xe5\xf9\xc1\x98\xd3\x1b\x9c\xb6\'v&\x14\x86-\x1c^\xad\x7f\xd2\xcb\xb9t(gh\xb9\xc5\x9c$\xdc@\x86\xa1\xc2\x98v\x9a\r\x05\xef\x99\x89\xe3\xcb\xe6\x1a\x89t\x04;\xb5@@E\xc2\x15\x9a\x9f6\xaf8\x9c\x04E\x08Qf\xb7\xbeD\xdc\xf8\xbag*?\xd5Zl\xa4\xabW\xcc[S\xe9"\x03c\xc7\xb0\r\xe0\x17+(.\x85?\x06\xbak\xdc\x8b\xba6A-\xf7c&\xc2\xbets\xb0\x0e\xe7h\xe8\xd6\r\x1a\x8d\xd7\xad8\x8b\xf4h\xdc\x15\xe3\x04\xf6\xbc\xe2\xae\x04\n\t\r\x83(k4\x0e\x15\x90\xeb\xc9z\xfc>\x14H\xf0S5P\xd3\x86\xacpn\x1f\xcc\xeej\x1b_\xeb\x1f\xcc\xeb\x01\xad\x16G\xab2w\xc0\xa7\xcb\xd6\xbd\xad9\xd5\x1f\x1cu\x9c6l\x9aQ\x8f\x8cu#\xb829s_\x05h\x90\x847J\xa4\x87`\xc9\xb0\x8d\xf8HGRw\xe6e\xbe\xb5\xfc\xa2\xfc\x1c\xc6"\xb7\x11%\x8c#\xe3\xeat\xf9\xf0\x1f\x08>o\x11\xe4X)\x8e\x08\x1e:\xc9qP\xc0p\xe5t\x98\xa7l\x91\x0c\x94\xe6c\x98E\xac\xfb\x13p\xd5\xc3/et- \xa6\xa2\x9d\x04\x18\xe0\x0b\xea\xe1\x96\xec\xb6^\x8d\x99\x80\xc2\x93\x8c\t\x8d\xf8\x10\xad\x8aD\xcc\x9cc\xb5ZR\xbc>6\x169\xect\x99\xa8Dn\x82\xff\x99\x1f\x07\xccX\xdf\xc0\xe5\x9e\x8dR\xc7\x89\xa98\xf2S\x86\xddI\xa6\x89\xd3rO\xf1\xeb\xf7&\xe8*\x93L^#\xa5\x95p\x99\xcb\xb0\xb2\xad\xf0\xfc\x80\xd2\xe2\xcd\x01\xb7\xccF\xda\x04\x8ed\x19K\xb4\x17\x81\x1aZ*/k\x0c\xdb\xb2\x03[\x14\x03-j\x0c%\xe3\xe6\xa3\x0e\xb61\xcf\xbe\x8f\x18\x06\x85\xf8\xf4r\xc0r \x03j\x02\xe9\x0f\xc4r\xe1\x01xw\xbe>6~\x84\xe9\x8d~N\xdc/\xfb\xb2\x18C\xfd\x9b\xfe\x81~\xa2\xfe\xef\xcew \xb8\x02\xe4\xb9KV]\xb7\xbb\xe0\r\xe1\x8f|\x84\xc0a\x1bZ8\xb3E\xc4\xd0M\xed\xa4\xd7\x92gR.f\xae\xb6\xc1`rT\xd6\xd4\x96-\x05\x0e3JL\xcf\xfe*\xf7lAx\x85Fgnz\x8byc^]\x9a\r\xce\xab\xc1/\xab\x0cG\xd0\xa9\xec\x94\xb2\xe6\x16\xfa\xfc\xc1M\xd2Xk\x0c>\xc4\x0f\xcd+\x82\xb7\xdbs5\x03\xf8\xc8vF\xb9FI\xfe\xc7T|\xbb\xfe1@I\x12\\#h\x96\x04\xf2\xb0^\xd4\x8c\xdaL\x1b\x1a\x83\x0f\xf9i\xca\xc5\xea\x01\x1f<,\xbc;6`R\xebf`Y]\xff\xc5<?>\xc9\xed\xca\xaf\'\x9d"\x83\x03/G!|\x86\xd8\xb7\x15P\x80\x14\x0e(?\xfe\x1c\xf9\x92f5\x1f\xb9\xa4\x17\xad\xba\xa9Ev\x84pr\x85\x99\x18\x97\x14\xaa\x8dg\x05\xaa\x0cop3\xa7\xa53\xe7\x1f5\x8a\x86Y\xe5:&\xad\x05X\xee=ev\x93\xb3\x06\xb0RJA\x17Rz\x12\xd8u\x93n}\x15P\xca\xc9\x08\xdb/\xd4\xecz\xbc\xf5\xba\xf7a\x9b\x81H\xda\x1aV\x08\xa2\n\x18\xcf\xe1/\x87L\xf6_7\x8c\xed\xfc\xeez\x16\xb2y\xe1\xc9(D\x175E\x91\xb2\xfe\xbb\xb1l=\xa3\x0f5s`\x1d\x0f\x04\x96&\xe0\x91@7\x91\x94\xf8\x1d\xf4\xccX\xd3k\xf4f\xfb\x81\xfb\n\r\xc8\x02&#n\x82)\xa7\xc4x\x8c\x161|z3\x0f\xeb\xd3g<\x86!f \x13K\xab\xcb\x93zqM\x03]\xc9PDaWbe\x1c\x01\xa6\x97\n \xd4\x8eKD\xbf]S\x81\x8f\xd3y\xd2\x08Z\xd9\xd9wc\x93\xb2]\xa7\x1c\x94\xe1e\xf0\x92\x9e\xe1\xb3r\xfe\x80\xf3J\xad\x0beq\x94\xfe\xa3\x15\x85%Z\x00\xe1\xc227\x95/\xfe\x0b\xf2\xfe\x93xE\'"\x9f\xca\xe1\x17\x8ds\xfe\xdc\xc1z\xe7Q\xca\xee\xb3\xf0\x845\xde3\x87C1\xc9\x0e\xa6\xfc\xf7\xa4\xa1#\x9fg\x12\xf5\xe7\xffG\xd7\x8b\xc1n6\x9aQ\xbc\x9fhY\xe6C\xd2\x16\x8b\xa0\x84)\xb8Y\x1b\x1d\xf0x\xd9*\x1f\xe3\x16\x86)\xa4\x91\xbfS\xea\xecV\xef\xec\x04\xc8\xa7\xc6g\x9eq\xe9m\xc4\xc0\r\x81f\x86}GNwq_KzX\xab\x16\xf7\xf6\xfbS\xe0\x97\xc9\x95/1a\x12\x01k\x0f\xe7\xed\xe4\xe6\x15\xb8p\xd1\xbd\xe9\xc1Nn\x96\x84y[\xb54?\x00\x86N\x1e\xeb.\xea\xd0\xae\x068\xc2~\x1fj6\xe5i\xb3\x9a\xbc6\xb6\x95\xcc\xf7>GZ\xf9v\x8c\x9f\x17_@\x9e8\xcd\x19\xd9\xa0\xe0\xcc\xb1\xf3\x05\x90\xeaKu\x19>\x9cYN#)\x0b\xa7\x97\xae?\x13\x0f\xe7\xd3\x7f!\x1b\xecG\xa7\xf2\'\x90\r\x87\xee\xee[\xd3vF\x88\xca1\xb8\xc9\x1d\xd3p\xb1\xe7\xad\xd09\x06\x1f\x02\x00W\xd9\x9b\x99d"fnz\x90;\xe3\x03\x06\x9b\x92\xc3\x03xq\x97g\xe6\xadR\xce(\xf9\x8c\xa4N\x86\x1fB+Y\xcd\xc1\xba\xbc\xa2\x1c8\xd2\xb1\xccP\xe2\\\xfa\x9e@\xca\xfbS\x9fp\xba\xab\xa8\xee\xe0\x8e\xdf\xbc#\xacd\x1aP\x1c4\xady\x17N\xe3\xc9\xe9<\xf0\xcfR\xb6\xa6p\xcf\xc8\x16[v\x9d"\x1fS\xebhCZ\x1f3\x13_\xc8\xb5\xb0\xaf\xe7F\xd9\xb98\x1a\x0c:`P\x01\x8b ^\xca\x94w7\xd5\xb5\xd2\x88|K\r\xa7:\x00\xe0\t\xedy\xa1\xc80\xd0g{\xa5\x85\xed33%J9\xdf\x19\x11rk\x0b]3Q\xda\xd0\x14\xe9\x98\xaeD&\x1b\xb9\x00\xb8\x9b-gI=\x19\xbf4E,\xfb<\x10\xf5\xf66/\x08\xcdy~&9\xfe\x8cf\xfeg\x13\x1dM]\x94\xcc\x17\xadid\xd6\xcb\xfaU\xf0\x95\xa5\xa1\x19<j\xaf\xe1z\xdb\xfe\x94\x9a\x85y\xcc\x14^\x8d\x1b\xd5\x0c\x1a\xe2z/\xf9\xe1\t/\xa4I\x80w\x8c\xcd\xe0\x97\xddi\x90\xed\xe0\x04-\xa3\x06\xc2\xddv9\xff\xb2l\x1b\\G\xd7cL1\xcb\x07\xafm\xb7)\xf7\x08\xef\xe7\xac7\xcd\x04\x0cd\x0cP\xff\x06\x97WFv\x8c\x9e\x054\xe09\xbd\xe5Io%\xf54\x9d\xab5\xea\xd1\xcb\xfe\xbe\xe11<B\xb6\x03y5\xe6\x98\xda<\x17gR\x84\x94J\xd3*E)\xab\xffG\xd5\xf3\xab\xaf\x02\xf9hE+\xc8\xd5\x87\xad\x95.N\xf1~\xca\xda\xd8MJ\x94\x1a\x02i\xe3\x8c\x11\xb0oU\xa6\x04\xb0\xdb\xd0D\'\xe7\x83\xb6\xd8\xad\xdd\x8d\xe65 u\xd3\xb8\x0b\xcc\xe1\xf1\x8av\x1a\x05\xee\xf1\x02\xbfz\xed1\x8a\xbb\xa1)\xe2P<\x81z\x14\x92/\n\xc9\xc8\x82\x9c\x85\xc4tc\x82[\xa2Q\xbb\x99\xc0\x9aP\xddZ\x11\xde\x0c\xb4\xd0\xcbl\xf6\x1e\x9b\x90S&}%m(\xed@\xcff\xea1\'\x83H\x93\xcb|f\xad\x8bvt\x80\xe5\x84\xac\x92\xee\x8d$\xc3\x8b\xb8\xc5X\xf5\x96O\xe1\x83L\x8b\xf3\x00\xb3\xf2\x13\xa2*J\xeb\x15\x85\x19*\x7f\xd3\xf1w$\xee*\xaf=<\x0cb\xe4c\x16\xa96\xe691\x06\xcd\xcc4\x0e\x9f_\xc4\x18\xb9\x1aEm\xcc\x01\x98\xb4Ns2\xc7WAg\x04\x8eM*\xc5\xc9\x8d\xbb\xfd\x84q&\x94V\xa0\xb4\xd74\x8ea\x9dY\x8bo\x86\xf6\xdeH\xcd\xff\xf4\xe5\xd9\xe5H\xc8ML\xf8\x94\x80\xb8\x88\x00\x82\xee\xe7\x9eN\x1f\xaeA\x85\xd9\x8f\x8b\x87\x8d\x94Tu\n.\xc0\x9d^\xe4\x8e\nt\xbbP\x93\xea\x01\xd9C|L\xdc\xf4\xcd\xaf\xbet\x95\x90\xafy\xff\x9b6\x91\x87\x1d\xa9\x16l2\x8d\xf8\xf0\x07Z\xb5\x938]\x0b\x1e\r\x1d\xd9\xea\x06G\xae\x06\xa0'
    #
    # print(tdes.decrypt(ciphertext3))
