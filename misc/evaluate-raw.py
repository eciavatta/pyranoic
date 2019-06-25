
"""
When a packet is captured the evaluate function is called.

Possible return values:
    - MARKED
    - SUSPICIOUS
    - NORMAL
    - FILTERED_OUT
"""

from fg.constants import *


def evaluate(packet):
    return NORMAL
