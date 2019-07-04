from pyranoic.constants import *


service_port = 80


def filter_function(packet):
    """
    Function called before evaluation to filter out unwanted packets.

    :param packet: The packet in-memory representation
    :return: True if the packet must be evaluated. False otherwise
    """

    return packet.haslayer('TCP') and (packet['TCP'].sport == service_port or packet['TCP'].dport == service_port)


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

    return NORMAL
