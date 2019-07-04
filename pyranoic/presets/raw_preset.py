from datetime import datetime

from .preset import Preset
from ..utils import *


class RawPreset(Preset):

    def __init__(self, project_path, evaluation_module):
        super().__init__(project_path, evaluation_module)
        self._timestamp_start = timestamp2hex(datetime.now().timestamp())[0:3]

    def analyze_packet(self, packet):
        identifier = timestamp2hex(packet.time)[3:]
        self.evaluate_and_submit(identifier, packet.time, packet)
