# GPG Agent

This is a custom GPG Agent that is compatible with open-source GPG/PGP (RFC 4880). The following algorithms are implemented manually: AES128/192/256 (ECB, CBC, OFB, GPG), 3DES (ECB, CBC, OFB, GPG), MD5, SHA1/2 (224, 256, 384, 512) and S2K salt (RFC 4880 mode 0, 1, 3). This program can encrypt and decrypt files only, no armor features. It uses a packet system for interpreting files and operations.

### Usage

```
usage: GPG Manager [-h] [-o OUTPUT] [-m {encrypt,decrypt}] [--cipher-algo {3DES,AES128,AES192,AES256}]
                   [--s2k-mode [0, 1, 3]] [--s2k-digest-algo {MD5,SHA1,SHA256,SHA384,SHA512,SHA224}]
                   [--s2k-count [1024-65011712]]
                   filename

En/decrypt a file using GPG

positional arguments:
  filename              file to en/decrypt

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        file to write encrypted data to
  -m {encrypt,decrypt}, --mode {encrypt,decrypt}
                        choose GPG mode
  --cipher-algo {3DES,AES128,AES192,AES256}
                        algorithm to encrypt with
  --s2k-mode [0, 1, 3]  mode for s2k
  --s2k-digest-algo {MD5,SHA1,SHA256,SHA384,SHA512,SHA224}
                        hash to use for S2K
  --s2k-count [1024-65011712]
                        count to use for S2K

Output to file
```
