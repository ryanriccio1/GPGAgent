# Author:   Ryan Riccio
# Program:  SHA2 Hash Implementation
# Date:     November 17th, 2022
from sha2.sha512 import SHA512


class SHA384(SHA512):
    _h = (0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
          0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4)

    def _digest(self):
        digest = (self._h[0] << 320) | (self._h[1] << 256) | (self._h[2] << 192) | \
                 (self._h[3] << 128) | (self._h[4] << 64) | self._h[5]
        return hex(digest)[2:].zfill(64)
