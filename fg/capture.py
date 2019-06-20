"""
Capture packets from local or remote interface and stream back to callback.
"""

import click
from os.path import join
from subprocess import Popen, PIPE
import sys

class Capture:

    _FILENAME = 'capture.pcap'
    _CALLBACK_INTERVAL = 5
    _MAX_FILESIZE = 64*1000

    def __init__(self, capture_dir='.', file_splitting_interval=60, disable_dns_resolution=True,
                 tshark_path='/usr/bin/tshark'):
        self._capture_dir = capture_dir
        self._file_splitting_interval = file_splitting_interval
        self._disable_dns_resolution = disable_dns_resolution
        self._tshark_path = tshark_path
        self._process = None

    def local_chunked_capture(self, interface):
        command = [
            self._tshark_path,
            '-b', f'interval:{self._file_splitting_interval}',
            '-b', f'filesize:{self._MAX_FILESIZE}',
            '-w', join(self._capture_dir, self._FILENAME),
            '-i', interface,
            '-q'
        ]
        if self._disable_dns_resolution:
            command.append('-n')

        try:
            self._process = Popen(command, stdin=None, stdout=PIPE, stderr=PIPE)
        except FileNotFoundError:
            click.echo(f'tshark is not installed (can\'t find in {self._tshark_path}', err=True)
            sys.exit(-1)

        message = self._process.stderr.readline()
        # self._process.stderr.close()

        return message

    def stop(self):
        if self._process is not None:
            self._process.kill()
