from os import devnull
from subprocess import Popen, PIPE

from .utils import *
from .constants import *

from os.path import join, exists

"""
Capture packets from local or remote interface and stream back to callback.
"""


class Capture:

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
            '-b', f'filesize:{MAX_CAPTURE_FILESIZE}',
            '-w', join(self._capture_dir, CAPTURE_FILENAME),
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
            '-n' if self._disable_dns_resolution else ''
        ]
        if not filters:
            command.extend(['not', 'port', '22'])  # exclude ssh traffic -> exponential
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
                '-b', f'filesize:{MAX_CAPTURE_FILESIZE}',
                '-w', join(self._capture_dir, CAPTURE_FILENAME),
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
