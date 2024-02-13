# Author:   Ryan Riccio
# Program:  SHA2 Hash Implementation
# Date:     November 17th, 2022
from sha2.sha256 import SHA256


class SHA224(SHA256):
    _h = (0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
          0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4)

    def _digest(self):
        digest = (self._h[0] << 192) | (self._h[1] << 160) | (self._h[2] << 128) | \
                 (self._h[3] << 96) | (self._h[4] << 64) | \
                 (self._h[5] << 32) | self._h[6]
        return hex(digest)[2:].zfill(56)
