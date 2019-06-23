
"""
When a packet is captured the apply_raw function is called.

Possible return values:
    - MARKED
    - SUSPICIOUS
    - NORMAL
    - FILTERED_OUT
"""

from fg.constants import *


def apply(packet):
    return NORMAL
