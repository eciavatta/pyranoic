from os import devnull
from os.path import exists, join
from subprocess import Popen, PIPE

import click

from .utils import fatal_error

"""
Capture packets from local or remote interface and stream back to callback.
"""


class Capture:

    _FILENAME = 'capture.pcap'
    _CALLBACK_INTERVAL = 5
    _MAX_FILESIZE = 64*1000

    def __init__(self, capture_dir, file_splitting_interval, disable_dns_resolution, tshark_path):
        self._capture_dir = capture_dir
        self._file_splitting_interval = file_splitting_interval
        self._disable_dns_resolution = disable_dns_resolution
        self._tshark_path = tshark_path
        self._process = None
        self._remote_process = None

    def local_capture(self, interface, filters):
        command = [
            self._tshark_path,
            '-b', f'interval:{self._file_splitting_interval}',
            '-b', f'filesize:{self._MAX_FILESIZE}',
            '-w', join(self._capture_dir, self._FILENAME),
            '-i', interface,
            '-q',
            '-n' if self._disable_dns_resolution else ''
        ]
        if filters:
            command.extend(filters)

        try:
            self._process = Popen(command, stdin=None, stdout=None, stderr=None)
        except FileNotFoundError:
            fatal_error(f'tshark is not installed (can\'t find in {self._tshark_path}')

    def remote_capture(self, host, interface, user, port, identity_file, live, wireshark_path, filters):
        if identity_file is not None and not exists(identity_file):
            fatal_error('The identity file provided not exists')

        command = [
            'ssh',
            f'{user}@{host}' if user is not None else host,
            '-p', str(port),
            '-i' if identity_file is not None else '', identity_file if identity_file is not None else '',
            self._tshark_path,
            '-w', '-',
            '-i', interface,
            '-q',
            '-n' if self._disable_dns_resolution else '',
        ]
        if not filters:
            if click.prompt('Do you want to exclude ssh traffic from capture', type=click.Choice(['yes', 'no']),
                            prompt_suffix='? ') == 'yes':
                command.extend(['not', 'port', '22'])
        else:
            command.extend(filters)

        self._remote_process = Popen(command, stdin=PIPE, stdout=PIPE, stderr=None)

        if live:
            ws_command = [
                wireshark_path,
                '-k',
                '-i', '-'
            ]
            self._process = Popen(ws_command, stdin=self._remote_process.stdout, stdout=None, stderr=open(devnull, 'w'))
        else:
            ts_command = [
                self._tshark_path,
                '-b', f'interval:{self._file_splitting_interval}',
                '-b', f'filesize:{self._MAX_FILESIZE}',
                '-w', join(self._capture_dir, self._FILENAME),
                '-i', '-',
                '-q'
            ]
            try:
                self._process = Popen(ts_command, stdin=self._remote_process.stdout, stdout=None,
                                      stderr=open(devnull, 'w'))
            except FileNotFoundError:
                fatal_error(f'tshark is not installed (can\'t find in {self._tshark_path}')

    def join(self):
        if self._process is not None:
            self._process.wait()

    def stop(self):
        if self._process is not None:
            self._process.kill()
        if self._remote_process is not None:
            self._remote_process.kill()
