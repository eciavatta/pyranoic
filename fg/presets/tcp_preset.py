from .preset import Preset


class TcpPreset(Preset):

    def analyze_packet(self, packet):
        print(packet)
