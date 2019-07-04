from pyranoic.constants import *


def filter_function(packet):
    """
    Function called before evaluation to filter out unwanted packets.

    :param packet: The packet in-memory representation
    :return: True if the packet must be evaluated. False otherwise
    """

    # select only ICMP packets
    return packet.haslayer('ICMP')


def evaluate_function(packet):
    """
    Function called to evaluate all selected packets.

    :param packet: The packet in-memory representation
    :return: a constant or a tuple of constant and string.
    The constant is the evaluation result of the packet. Possible values are:
        - MARKED
        - SUSPICIOUS
        - NORMAL
        - FILTERED_OUT
    The comment is a string associated with the evaluation.
    """

    if packet['IP'].src == '8.8.8.8':
        return MARKED, 'Google ping response'
    elif packet['IP'].dst == '8.8.8.8':
        return MARKED, 'Google ping request'

    return NORMAL
