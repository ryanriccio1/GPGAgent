# Author:   Ryan Riccio
# Program:  GPG Packet Parser
# Date:     November 17th, 2022
from gpg_packet.packet_consts import *
from gpg_packet.packet import *


def _get_packets(file_handle):
    """
    Extract packets from file.

    :param file_handle: File handle like open(file, 'r')
    :return: list[Packet]
    """
    packets = []

    # RFC 4880: 4.2
    # assigns byte and if byte exists, returns true, if not, we are at EOF
    while byte := file_handle.read(1):
        # if header is valid
        if byte[0] & 0x80 == 0x80:
            # get the byte offset (we already read the first byte, so subtract 1 from the offset
            starting_offset = file_handle.tell() - 1
            ctb = byte[0]  # get the value of the starting byte

            # if the header is in new format
            if byte[0] & 0x40 == 0x40:
                new = True  # we are new format
                tag = byte[0] & 0x3F  # get the tag
                hlen = 2  # hlen is at least 2
                plen = int.from_bytes(file_handle.read(1), byteorder="big")  # plen length is based on value of plen
                if 255 > plen > 191:
                    plen = ((plen - 192) << 8) + int.from_bytes(file_handle.read(1), byteorder="big") + 192
                    hlen += 1
                if plen == 255:
                    second_octet = int.from_bytes(file_handle.read(1), byteorder="big")
                    third_octet = int.from_bytes(file_handle.read(1), byteorder="big")
                    fourth_octet = int.from_bytes(file_handle.read(1), byteorder="big")
                    fifth_octet = int.from_bytes(file_handle.read(1), byteorder="big")
                    plen = (second_octet << 24) | (third_octet << 16) | (fourth_octet << 8) | fifth_octet
                    hlen += 4

            # header is in old format
            else:
                new = False  # we are not new format
                tag = (byte[0] & 0x3C) >> 2  # get the tag type
                len_type = byte[0] & 0x3  # get the length type
                if len_type == 0:
                    hlen = 2
                    plen = int.from_bytes(file_handle.read(1), byteorder="big")
                if len_type == 1:
                    hlen = 3
                    plen = int.from_bytes(file_handle.read(2), byteorder="big")
                if len_type == 2:
                    hlen = 5
                    plen = int.from_bytes(file_handle.read(4), byteorder="big")
                # indeterminate len type
                if len_type == 3:
                    hlen = 1
                    plen = None

            tag = get_tag(tag)
            header = PacketHeader(starting_offset, ctb, tag, hlen, plen, new)
            data = file_handle.read(plen)
            if tag.value == 3:
                match data[2]:
                    case 0:
                        data = PacketS2K0(data[1], data[3])
                    case 1:
                        data = PacketS2K1(data[1], data[3], data[4:12])
                    case 3:
                        data = PacketS2K3(data[1], data[3], data[4:12], data[12])
            else:
                data = PacketData(data)
            packets.append(Packet(header, data))
        else:
            raise ValueError(f"Invalid Packet at offset {file_handle.tell()}.")

    return packets


def categorize_packets(packets):
    """
    Categorize packets as either 'S2K' or 'encrypted' for better code readability.

    :param packets: Packets to categorize.
    :return: Dictionary of packets.
    :rtype: dict[str, Packet]
    """
    organized_packets = {
        "S2K": None,
        "encrypted": None
    }
    for packet in packets:
        # allow tag value to either be tag instance or literal value
        if isinstance(packet.header.tag, Tag):
            if packet.header.tag.value == 3:
                organized_packets["S2K"] = packet
            if packet.header.tag.value == 18:
                organized_packets["encrypted"] = packet
        else:
            if packet.header.tag == 3:
                organized_packets["S2K"] = packet
            if packet.header.tag == 18:
                organized_packets["encrypted"] = packet
    return organized_packets


def process_literal_data(decrypted_data, encryption_algorithm):
    """
    Take a decrypted literal data packet and extract the information.

    :param decrypted_data: Decrypted data packet.
    :param encryption_algorithm: Encryption algorithm used.
    :return: Literal data packet.
    :rtype: Packet
    """
    # ignore the random characters (assume they've already been checked)
    decrypted_data = decrypted_data[encryption_algorithm.block_len + 2:]
    len_type = decrypted_data[0] & 0x3  # get the length type
    if len_type == 0:
        hlen = 2
        plen = decrypted_data[1]
    if len_type == 1:
        hlen = 3
        plen = int.from_bytes(decrypted_data[1:3], byteorder='big')
    if len_type == 2:
        hlen = 5
        plen = int.from_bytes(decrypted_data[1:5], byteorder='big')

    lit_data_header = PacketHeader(off=0, ctb=decrypted_data[0], tag=11, hlen=hlen, plen=plen, new=False)
    # read only plen (anything after plen is mdc packet)
    lit_data_packet = PacketLiteralData(decrypted_data[hlen:lit_data_header.plen + 2])
    return Packet(lit_data_header, lit_data_packet)


def parse_file(filename, display_packets=False):
    """
    Parse GPG packets from a file.

    :param filename: file to parse.
    :param display_packets: Show the parsed packets.
    :return: List of all found packets.
    :rtype: list[Packet]
    """
    with open(filename, "rb") as file:
        packets = _get_packets(file)

    if display_packets:
        for packet in packets:
            for header, data in packet:
                print(f"# off={header.off} ctb={hex(header.ctb)[2:]} tag={header.tag.value} "
                      f"hlen={header.hlen} plen={header.plen} {'new-ctb' if header.new else ''}")
                print(f":{header.tag.name}:")
    return packets


if __name__ == "__main__":
    import sys
    import os.path

    if not len(sys.argv) > 1:
        raise ValueError("Filename must be given")
    if not os.path.exists(sys.argv[1]):
        raise ValueError("File does not exist")
    parse_file(sys.argv[1])
