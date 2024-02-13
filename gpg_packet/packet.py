# Author:   Ryan Riccio
# Program:  GPG Packet Definitions
# Date:     November 17th, 2022
import gpg_packet.packet_consts as consts
import gpg_packet.constructor as constructor


class PacketHeader(object):
    # RFC 4880: 4.2
    def __init__(self, off, ctb, tag, hlen, plen, new=False):
        """
        Store data for GPG packet header.

        :param off: Byte offset.
        :param ctb: Starting byte.
        :param tag: Packet tag.
        :param hlen: Header length.
        :param plen: Packet length.
        :param bool new: New or old format.
        """
        self.off = off
        self.ctb = ctb
        self.tag = tag
        self.hlen = hlen
        self.plen = plen
        self.new = new
        self.byte_form = constructor.header_to_bytes(self)

    # this does not need to be properties, but this was done thinking there would be more
    # processing in the getters and setters, and pycharm type hinting likes these better,
    # so no reason to change.
    @property
    def off(self):
        return self._off

    @property
    def ctb(self):
        return self._ctb

    @property
    def tag(self):
        return self._tag

    @property
    def hlen(self):
        return self._hlen

    @property
    def plen(self):
        return self._plen

    @property
    def new(self):
        return self._new

    @property
    def byte_form(self):
        return self._byte_form

    @off.setter
    def off(self, value):
        self._off = value

    @ctb.setter
    def ctb(self, value):
        self._ctb = value

    @tag.setter
    def tag(self, value):
        self._tag = value

    @hlen.setter
    def hlen(self, value):
        self._hlen = value

    @plen.setter
    def plen(self, value):
        self._plen = value

    @new.setter
    def new(self, value):
        self._new = value

    @byte_form.setter
    def byte_form(self, value):
        self._byte_form = value


class PacketData(object):
    def __init__(self, data):
        """
        Store GPG data separate from the header.

        :param bytes data: Data to store.
        """
        self.data = data


class Packet(object):
    # RFC 4880: 4
    def __init__(self, header, data):
        """
        Store both the header and the data in a single object.

        :param PacketHeader header: Packet header.
        :param data: PacketData.
        """
        self.header = header
        self.data = data

    def __iter__(self):
        """ Whenever we iterate over this object, return a tuple of the header and the data. """
        yield self.header, self.data


class PacketS2K0(PacketData):
    mode = 0

    # RFC 4880: 3.7, 4.3
    def __init__(self, enc_algorithm, hash_algorithm):
        """
        Store S2K mode 0 packet data.

        :param enc_algorithm: Value to use to query for encryption algorithm.
        :param hash_algorithm: Value to use to query for hash algorithm.
        """
        self.encryption_algorithm = consts.get_sym_algorithm(enc_algorithm)
        self.hash_algorithm = consts.get_hash_algorithm(hash_algorithm)
        # store version 4 (only version) and the byte representations of all the data.
        super().__init__(b"\x04" + enc_algorithm.to_bytes(1, byteorder='big') +
                         self.mode.to_bytes(1, byteorder='big') + hash_algorithm.to_bytes(1, byteorder='big'))


class PacketS2K1(PacketS2K0):
    mode = 1

    # RFC 4880: 3.7, 4.3
    def __init__(self, enc_algorithm, hash_algorithm, salt):
        """
        Store S2K mode 1 packet data.

        :param enc_algorithm: Value to use to query for encryption algorithm.
        :param hash_algorithm: Value to use to query for hash algorithm.
        :param salt: Salted data to use during key generation.
        """
        self.salt = salt
        super().__init__(enc_algorithm, hash_algorithm)
        self.data += salt


class PacketS2K3(PacketS2K1):
    mode = 3

    # RFC 4880: 3.7, 4.3
    def __init__(self, enc_algorithm, hash_algorithm, salt, count):
        """
        Store S2K mode 3 packet data.

        :param enc_algorithm: Value to use to query for encryption algorithm.
        :param hash_algorithm: Value to use to query for hash algorithm.
        :param salt: Salted data to use during key generation.
        :param count: Count to use during key generation.
        """
        self.count = count
        super().__init__(enc_algorithm, hash_algorithm, salt)
        self.data += count.to_bytes(1, byteorder="big")


class PacketLiteralData(PacketData):
    # RFC 4880: 5.9
    def __init__(self, data):
        """
        Will split literal data into PacketData. (mode, filename_len, filename, file_time, text)

        :param data: Data to store in packet.
        """
        self.mode = data[0]
        self.filename_len = data[1]
        self.filename = data[2:self.filename_len + 2]
        self.file_time = data[2 + self.filename_len:6 + self.filename_len]
        self.text = data[6 + self.filename_len:]
        super().__init__(data)
