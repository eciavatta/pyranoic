import gzip
import io
import re
import sys
import zlib

import click
from CaseInsensitiveDict import CaseInsensitiveDict

from .tcp_preset import TcpPreset
from ..utils import *


class HttpPreset(TcpPreset):

    def __init__(self, project_path, evaluation_module):
        super().__init__(project_path, evaluation_module)

    def _evaluate_conversation(self, connection_hash, packets, conversation):
        timestamp = packets[0].time

        prev_request = None
        for i in range(len(conversation)):
            is_request = conversation[i][0]
            message = conversation[i][1]

            if is_request:
                if prev_request:
                    self.evaluate_and_submit(prev_request.identifier + 'ff', prev_request.timestamp,
                                             (prev_request, None), 'Nope')

                identifier = timestamp2hex(packets[0].time)[3:] + timestamp2hex(packets[-1].time)[3:]
                identifier += connection_hash + self._sequence_hash(i)
                prev_request = HttpRequest.try_parse(identifier, timestamp, message)
            else:
                if not prev_request:
                    continue

                response = HttpResponse.try_parse(message)
                self.evaluate_and_submit(prev_request.identifier + self._sequence_hash(i), prev_request.timestamp,
                                         (prev_request, response), 'Nope')
                prev_request = None

    def describe(self, identifier, out_file):
        if len(identifier) != 28:
            click.echo('Invalid stream identifier', err=True)
            return

        connection_id = identifier[:24]
        request_index = int(identifier[24:26], 16)
        response_index = int(identifier[26:], 16)
        conversation = self._load_conversation(connection_id)
        timestamp = hex2timestamp(self._timestamp_start + identifier[:8])

        if not out_file:
            if request_index < len(conversation) and conversation[request_index][0]:
                request = HttpRequest.try_parse(identifier, timestamp, conversation[request_index][1])
            else:
                request = None

            if response_index < len(conversation) and not conversation[response_index][0]:
                response = HttpResponse.try_parse(conversation[response_index][1])
            else:
                response = None

            sys.stdout.write(str(request) if request else 'No request found.')
            sys.stdout.write(str(response) if response else 'No response found.')

    @staticmethod
    def _sequence_hash(sequence_index):
        return "{0:0{1}x}".format(sequence_index, 2)


class HttpRequest:

    _request_regex = re.compile(r'^(.+)\s+(.*?)\s+(.+?)\s*$')
    _header_regex = re.compile(r'^(.+)\s*:\s*(.*?)\s*$')

    def __init__(self, identifier, timestamp, method, url, version, headers, body):
        self.identifier = identifier
        self.timestamp = timestamp
        self.method = method
        self.url = url
        self.version = version
        self.headers = headers
        self.body = body

    def __str__(self):
        string = ''
        string += f'<HttpRequest> id=\'{self.identifier}\' datetime=\'{timestamp2str(self.timestamp)}\'\n'
        string += f'{self.method} {self.url} {self.version}\r\n'
        for key, value in self.headers.items():
            string += f'{key.title()}: {value}\r\n'
        string += '\r\n'

        #if self.body:
        #    string += self.body.decode() #_decoded()

        return string

    def body_decoded(self):

        if 'content-encoding' in self.headers:
            content_encoding = self.headers['content-encoding'].lower()
            if 'deflate' in content_encoding:
                return zlib.decompress(self.body, 16 + zlib.MAX_WBITS)
            elif 'gzip' in content_encoding:
                buffer = io.BytesIO(self.body)
                size = buffer.readline()
                data = buffer.read(int(size, 16))
                buffer.close()

                return gzip.decompress(data)
            else:
                return self.body.decode()

    @staticmethod
    def try_parse(identifier, timestamp, payload):
        buffer = io.BytesIO(payload)

        request_match = HttpRequest._request_regex.match(buffer.readline().decode())
        if request_match and len(request_match.groups()) == 3:
            method = request_match.group(1)
            url = request_match.group(2)
            version = request_match.group(3)
        else:
            return None

        headers = CaseInsensitiveDict()
        line = buffer.readline()
        while line:
            header_match = HttpRequest._header_regex.match(line.decode())
            if header_match and len(header_match.groups()) == 2:
                headers[header_match.group(1)] = header_match.group(2)
            else:
                break

            line = buffer.readline()

        body = buffer.read()
        buffer.close()

        return HttpRequest(identifier, timestamp, method, url, version, headers, body)


class HttpResponse:
    _request_regex = re.compile(r'^(.+)\s+(\d+)\s+(.+?)\s*$')
    _header_regex = re.compile(r'^(.+)\s*:\s*(.+?)\s*$')

    def __init__(self, version, status_code, status_desc, headers, body):
        self.version = version
        self.status_code = status_code
        self.status_desc = status_desc
        self.headers = headers
        self.body = body

    def __str__(self):
        string = ''
        string += f'<HttpResponse>\n'
        string += f'{self.version} {self.status_code} {self.status_desc}\r\n'
        for key, value in self.headers.items():
            string += f'{key.title()}: {value}\r\n'
        string += '\r\n'

        if self.body:
            string += self.body_decoded()

        return string

    def body_decoded(self):
        if 'content-encoding' in self.headers:
            content_encoding = self.headers['content-encoding'].lower()
            if 'deflate' in content_encoding:
                return zlib.decompress(self.body, 16 + zlib.MAX_WBITS)
            elif 'gzip' in content_encoding:
                print('ok')
                buffer = io.BytesIO(self.body)
                #size = buffer.readline()
                #data = buffer.read(int(size, 16))
                #buffer.close()

                return gzip.decompress(buffer.read())
            else:
                return self.body.decode()

    @staticmethod
    def try_parse(payload):
        buffer = io.BytesIO(payload)

        request_match = HttpResponse._request_regex.match(buffer.readline().decode())
        if request_match and len(request_match.groups()) == 3:
            version = request_match.group(1)
            status_code = request_match.group(2)
            status_desc = request_match.group(3)
        else:
            return None

        headers = CaseInsensitiveDict()
        line = buffer.readline()
        while line:
            header_match = HttpResponse._header_regex.match(line.decode())
            if header_match and len(header_match.groups()) == 2:
                headers[header_match.group(1)] = header_match.group(2)
            else:
                break

            line = buffer.readline()

        body = buffer.read()
        buffer.close()

        return HttpResponse(version, status_code, status_desc, headers, body)
