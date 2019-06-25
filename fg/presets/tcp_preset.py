import sys
from binascii import unhexlify
from datetime import datetime
from os import remove
from subprocess import Popen, PIPE
from tempfile import mkstemp

import click
from scapy.all import wrpcap

from .preset import Preset
from ..utils import *


class TcpPreset(Preset):

    def __init__(self, project_path, evaluation_module):
        super().__init__(project_path, evaluation_module)
        self._timestamp_start = timestamp2hex(datetime.now().timestamp())[0:3]
        self._connections = {}
        self._start_handshaking = {}
        self._close_handshaking = {}

    def analyze_packet(self, packet):
        if not packet.haslayer('TCP'):
            return

        tcp = packet['TCP']
        sport = self._port_hash(tcp.sport)
        dport = self._port_hash(tcp.dport)

        if f'{sport}{dport}' in self._connections:
            connection_hash = f'{sport}{dport}'
        elif f'{dport}{sport}' in self._connections:
            connection_hash = f'{dport}{sport}'
        else:
            connection_hash = None

        if not connection_hash:
            if 'S' in tcp.flags and 'A' not in tcp.flags:  # SYN, not ACK
                stream_hash = f'{sport}{dport}'
                if stream_hash not in self._start_handshaking:
                    self._start_handshaking[stream_hash] = [packet]
            elif 'S' in tcp.flags and 'A' in tcp.flags:  # SYN, ACK
                stream_hash = f'{dport}{sport}'
                if stream_hash in self._start_handshaking and len(self._start_handshaking[stream_hash]) == 1:
                    self._start_handshaking[stream_hash].append(packet)
            elif 'A' in tcp.flags:
                stream_hash = f'{sport}{dport}'
                if stream_hash in self._start_handshaking and len(self._start_handshaking[stream_hash]) == 2:
                    self._start_handshaking[stream_hash].append(packet)
                    self._connections[stream_hash] = self._start_handshaking[stream_hash]
                    self._close_handshaking[stream_hash] = 0
                    del self._start_handshaking[stream_hash]
            return

        self._connections[connection_hash].append(packet)

        if 'F' in tcp.flags and 'A' in tcp.flags:
            self._close_handshaking[connection_hash] += 1

        if ('A' in tcp.flags and self._close_handshaking[connection_hash] == 2) or 'R' in tcp.flags:
            self._evaluate_stream(connection_hash)

    def _evaluate_stream(self, connection_hash):
        packets = self._connections[connection_hash]
        ports = int(connection_hash[:4], 16), int(connection_hash[4:], 16)
        tmp_file = mkstemp(suffix='.pcap')[1]
        wrpcap(tmp_file, packets)

        conversation = self._follow_stream(tmp_file)
        remove(tmp_file)

        del self._connections[connection_hash]
        del self._close_handshaking[connection_hash]

        stream_identifier = timestamp2hex(packets[0].time)[3:] + timestamp2hex(packets[-1].time)[3:] + connection_hash
        duration = '{:.3f}'.format(packets[-1].time - packets[0].time)
        self.evaluate_and_submit(stream_identifier, packets[0].time, conversation,
                                 f'TCP ports: {ports[0]} → {ports[1]}, duration: {duration} s')

    def describe(self, identifier, out_file):
        if len(identifier) != 24:
            click.echo('Invalid stream identifier', err=True)
            return

        conversation = self._load_conversation(identifier)

        if not out_file:
            for entry in conversation:
                sys.stdout.write(click.style(entry[1].decode('utf-8'), fg='red' if entry[0] else 'blue'))
        else:
            with open(out_file, 'wb') as file:
                for entry in conversation:
                    file.write('' if entry[0] else '\t' + entry[1] + '\n')

    def generate_exploit(self, identifier, out_file):
        if len(identifier) != 24:
            click.echo('Invalid stream identifier', err=True)
            return

        conversation, info = self._load_conversation(identifier, return_info=True)

        info = info[1][8:-1].decode('utf-8').split(':')  # format = "Node 1: 10.10.8.1:9876\n"
        exploit = 'from pwn import *\n\n'
        exploit += f'io = remote(\'{info[0]}\', {info[1]})\n'

        exploit.splitlines()
        for i in range(len(conversation)):
            current_message = conversation[i][1]

            if not conversation[i][0]:  # is receiver
                if i+1 < len(conversation) and conversation[i+1][0]:  # if next message is from initiator
                    if len(conversation[i][1]) > 8:
                        limit = conversation[i][1][-8:]
                    else:
                        limit = conversation[i][1]
                    exploit += f'io.recvuntil({limit})\n'
            else:  # is initiator
                packed = pack_string(current_message)
                if packed.count('\n') > 0:
                    for msg in packed.splitlines():
                        exploit += f'io.sendline(\'{msg}\')\n'
                else:
                    exploit += f'io.send(\'{packed}\')\n'

        if not out_file:
            sys.stdout.write(exploit)
        else:
            with open(out_file, 'w') as file:
                file.write(exploit)

    def _load_conversation(self, identifier, return_info=False):
        start_timestamp = hex2timestamp(self._timestamp_start + identifier[:8])
        end_timestamp = hex2timestamp(self._timestamp_start + identifier[8:16])
        ports = int(identifier[16:20], 16), int(identifier[20:24], 16)

        chunks = list_chunks_between_timestamps(self._project_path, start_timestamp, end_timestamp)
        chunks = full_chunks_path(self._project_path, chunks)
        if len(chunks) == 0:
            click.echo('Cannot find the packet capture related to that identifier')
            return

        pipe = self._filter_chunks(chunks, ports)
        return self._follow_stream('-', pipe, return_info)

    @staticmethod
    def _follow_stream(file_path, stdin=None, return_info=False):
        conversation = []

        ts_command = [
            '/usr/bin/tshark',  # TODO: replace hardcoded path
            '-r', file_path,
            '-z', 'follow,tcp,raw,0',
            '-q'
        ]
        process = Popen(ts_command, stdin=stdin, stdout=PIPE, stderr=sys.stderr)
        tshark_output = process.stdout.readlines()

        output = tshark_output[6:-1]  # remove tshark banner

        for line in output:
            if chr(line[0]) == '\t':
                is_initiator = False
                raw = line[1:-1]
            else:
                is_initiator = True
                raw = line[0:-1]

            conversation.append((is_initiator, unhexlify(raw)))

        if return_info:
            return conversation, tshark_output[4:6]
        return conversation

    @staticmethod
    def _filter_chunks(chunks, ports):
        ts_command = [
            '/usr/bin/tshark',  # TODO: replace hardcoded path
            '-r', '-',
            '-w', '-',
            '-q',
            'tcp.port', '==', f'{ports[0]}', 'and', 'tcp.port', '==', f'{ports[1]}'
        ]
        process = Popen(ts_command, stdin=PIPE, stdout=PIPE, stderr=sys.stderr)
        for chunk_path in chunks:
            with open(chunk_path, 'rb') as chunk_file:
                process.stdin.write(chunk_file.read())
        process.stdin.close()

        return process.stdout

    @staticmethod
    def _port_hash(port):
        return "{0:0{1}x}".format(port, 4)
