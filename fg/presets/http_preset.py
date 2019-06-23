from .preset import Preset


class HttpPreset(Preset):

    def analyze_packet(self, packet):
        print(packet)
