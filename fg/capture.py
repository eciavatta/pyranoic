import sys
from os.path import exists, join
from subprocess import Popen, PIPE

import click

"""
Capture packets from local or remote interface and stream back to callback.
"""


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

    def local_capture(self, interface):
        command = [
            self._tshark_path,
            '-b', f'interval:{self._file_splitting_interval}',
            '-b', f'filesize:{self._MAX_FILESIZE}',
            '-w', join(self._capture_dir, self._FILENAME),
            '-i', interface,
            '-q',
            '-n' if self._disable_dns_resolution else ''
        ]
        if self._disable_dns_resolution:
            command.append('-n')

        try:
            self._process = Popen(command, stdin=None, stdout=None, stderr=PIPE)
        except FileNotFoundError:
            click.echo(f'tshark is not installed (can\'t find in {self._tshark_path}', err=True)
            sys.exit(-1)

        message = self._process.stderr.readline()
        # self._process.stderr.close()

        return message

    def remote_capture(self, host, interface, user=None, port=22, password=None, identity_file=None, live=False,
                       wireshark_path='/usr/bin/wireshark'):
        if identity_file is not None and not exists(identity_file):
            click.echo('The identity file provided not exists')
            sys.exit(-1)

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
            'not', 'port', '22'
        ]

        remote_process = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
        if password is not None:
            remote_process.communicate(password)

        if live:
            ws_command = [
                wireshark_path,
                '-k',
                '-i', '-'
            ]
            Popen(ws_command, stdin=remote_process.stdout, stdout=None, stderr=None)

            return remote_process.stderr.readline()
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
                self._process = Popen(ts_command, stdin=remote_process.stdout, stdout=None, stderr=PIPE)
            except FileNotFoundError:
                click.echo(f'tshark is not installed (can\'t find in {self._tshark_path}', err=True)
                sys.exit(-1)

            return self._process.stderr.readline()

    def join(self):
        if self._process is not None:
            self._process.wait()

    def stop(self):
        if self._process is not None:
            self._process.kill()
