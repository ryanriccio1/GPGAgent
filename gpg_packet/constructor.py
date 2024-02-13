# Author:   Ryan Riccio
# Program:  GPG Packet Constructor
# Date:     November 17th, 2022
from gpg_packet.packet_consts import Tag


def header_to_bytes(header):
    """
    Convert a PacketHeader to bytes.

    :param gpg_packet.packet.PacketHeader header: Header to convert to bytes.
    :return: Header represented as bytes.
    :rtype: bytes
    """
    # start the header with the valid bit
    header_bytes = bytearray(b"\x80")
    # RFC 4880: 4.2
    if header.new:
        # add the tag (allow programmer to specify tag as value rather than Tag instance)
        if isinstance(header.tag, Tag):
            header_bytes[0] = header_bytes[0] | 0x40 | header.tag.value
        else:
            header_bytes[0] = header_bytes[0] | 0x40 | header.tag
        # RFC 4880: 4.2.2
        # add the packet length

        # RFC 4880: 4.2.2.1
        if 0 < header.plen < 192:
            header_bytes += header.plen.to_bytes(1, byteorder='big')

        # RFC 4880: 4.2.2.2
        elif 191 < header.plen < 8384:
            first_octet = ((header.plen - 192) >> 8) + 192
            second_octet = (header.plen - 192 - ((first_octet - 192) << 8))
            header_bytes += first_octet.to_bytes(1, byteorder='big')
            header_bytes += second_octet.to_bytes(1, byteorder='big')

        # RFC 4880: 4.2.2.3
        elif 8383 < header.plen < 4294967296:
            # perform addition before converting to bytes
            first_octet = 255
            second_octet = (header.plen >> 24)
            third_octet = ((header.plen - (second_octet << 24)) >> 16)
            fourth_octet = ((header.plen - (third_octet << 16)) >> 8)
            fifth_octet = (header.plen - (fourth_octet << 8))

            first_octet = first_octet.to_bytes(1, byteorder='big')
            second_octet = second_octet.to_bytes(1, byteorder='big')
            third_octet = third_octet.to_bytes(1, byteorder='big')
            fourth_octet = fourth_octet.to_bytes(1, byteorder='big')
            fifth_octet = fifth_octet.to_bytes(1, byteorder='big')

            header_bytes += first_octet + second_octet + third_octet + fourth_octet + fifth_octet

    else:
        # add the tag (allow programmer to specify tag as value rather than Tag instance)
        if isinstance(header.tag, Tag):
            header_bytes[0] = header_bytes[0] | (header.tag.value << 2)
        else:
            header_bytes[0] = header_bytes[0] | (header.tag << 2)
        # RFC 4880: 4.2.1
        # add the length type and packet length
        if header.hlen == 2:
            header_bytes[0] = header_bytes[0] | 0
            header_bytes += header.plen.to_bytes(1, byteorder='big')
        elif header.hlen == 3:
            header_bytes[0] = header_bytes[0] | 1
            header_bytes += header.plen.to_bytes(2, byteorder='big')
        elif header.hlen == 5:
            header_bytes[0] = header_bytes[0] | 2
            header_bytes += header.plen.to_bytes(4, byteorder='big')
        else:
            header_bytes[0] = header_bytes[0] | 3

    # return byte representation
    return header_bytes


def get_hlen(plen):
    """
    Using the rules for old packet format, calculate the header length based on packet length.

    :param int plen: Packet length to use.
    :return: Length of header.
    :rtype: int
    """
    # RFC 4880: 4.2.2
    if plen < 256:
        return 2
    if plen < 65536:
        return 3
    if plen < 4294967296:
        return 5
