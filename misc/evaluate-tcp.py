from pyranoic.constants import *
import re


service_port = 9876
flag_regex = re.compile(r'[A-Z0-9]{31}=')
illegal_chars_regex = re.compile(r'-')


def filter_function(packet):
    """
    Function called before evaluation to filter out unwanted packets.

    :param packet: The packet in-memory representation
    :return: True if the packet must be evaluated. False otherwise
    """

    # EXAMPLE

    return packet.haslayer('TCP') and (packet['TCP'].sport == service_port or packet['TCP'].dport == service_port)


def evaluate_function(conversation):
    """
    Function called to evaluate an entire TCP conversation.

    :param conversation: A list of tuple<boolean, bytes>. The first first value is True if the message came from the
                         initiator of conversation. The message is in bytes representation.
    :return: a constant or a tuple of constant and string.
    The constant is the evaluation result of the packet. Possible values are:
        - MARKED
        - SUSPICIOUS
        - NORMAL
        - FILTERED_OUT
    The comment is a string associated with the evaluation.
    """

    # EXAMPLE

    for elem in conversation:
        is_initiator = elem[0]
        decoded_message = elem[1].decode()

        if is_initiator:
            if illegal_chars_regex.match(decoded_message):
                return MARKED, 'An illegal char is sent to the service'

            if flag_regex.match(decoded_message):
                return NORMAL, 'Master insert the flag'
        else:
            if flag_regex.match(decoded_message):
                return NORMAL, 'Master check the flag'

    return SUSPICIOUS, 'Unmatched conversation'
