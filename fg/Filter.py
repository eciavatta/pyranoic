import pyshark
from collections import defaultdict

#cap = pyshark.FileCapture('~/traffic/prova.cap')

filtered_cap = pyshark.FileCapture('~/traffic/prova.pcap', display_filter='tcp')

stream = defaultdict(list)

for packet in filtered_cap:
    source = packet.ip.src
    destination = packet.ip.dst
    connection = source + destination
    if connection not in stream:
        stream[connection] = [packet]
    else:
        stream[connection].append(packet)

print(connection)




