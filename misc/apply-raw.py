
"""
When a packet is captured the apply_raw function is called.

Possible return values:
    - MARKED
    - SUSPICIOUS
    - NORMAL
    - FILTER_OUT
"""

from fg.constants import *


def apply_raw(packet):
    return NORMAL
