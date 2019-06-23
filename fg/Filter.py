import pyshark
from collections import defaultdict

# cap = pyshark.FileCapture('~/traffic/prova.cap')

filtered_cap = pyshark.FileCapture('/home/gio/traffic/prova.pcap', display_filter='tcp')

stream = defaultdict(list)

for packet in filtered_cap:
    source_ip = packet.ip.src
    destination_ip = packet.ip.dst

    source_port = packet.tcp.port
    destination_port = packet.tcp.dstport

    source = (source_ip, source_port)
    dest = (destination_ip, destination_port)

    if (dest, source) in stream:
        stream[(dest, source)].append(packet)

    else:
        stream[(source, dest)].append(packet)


print(stream)



