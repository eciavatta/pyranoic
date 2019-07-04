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
        requests = []
        current_request = None
        current_request_index = -1
        current_response = None
        current_response_index = -1
        for i in range(len(conversation)):
            is_request = conversation[i][0]
            message = conversation[i][1]

            if is_request:
                if current_response:
                    requests.append((current_request, current_request_index, current_response, current_response_index))
                    current_request = None
                    current_request_index = -1
                    current_response = None
                    current_response_index = -1

                if not current_request:
                    current_request = message
                    current_request_index = i
                else:
                    current_request += message
            else:
                if not current_response:
                    current_response = message
                    current_response_index = i
                else:
                    current_response += message

        if current_request or current_response:
            requests.append((current_request, current_request_index, current_response, current_response_index))

        for req_res in requests:
            request_index = req_res[1]
            response_index = req_res[3]
            identifier = timestamp2hex(packets[0].time)[3:] + timestamp2hex(packets[-1].time)[3:]
            identifier += connection_hash + self._sequence_hash(request_index) + self._sequence_hash(response_index)

            try:
                request = HttpRequest.try_parse(identifier, packets[0].time, req_res[0]) if req_res[0] else None
                response = HttpResponse.try_parse(req_res[2]) if req_res[0] else None
            except Exception as e:
                return self.exceptionally_submit(f'Error in parsing request/response: {str(e)}', identifier,
                                                 packets[0].time)

            additional_info = ''
            additional_info += request.__repr__() if request else '@Nope'
            additional_info += ' → '
            additional_info += response.__repr__() if response else '@Nope'

            self.evaluate_and_submit(identifier, packets[0].time, (request, response), additional_info)

    def describe(self, identifier, out_file):
        if len(identifier) != 28:
            click.echo('Invalid stream identifier', err=True)
            return

        connection_id = identifier[:24]
        request_index = int(identifier[24:26], 16)
        response_index = int(identifier[26:], 16)
        conversation = self._load_conversation(connection_id)
        timestamp = hex2timestamp(self._timestamp_start + identifier[:8])

        if request_index < len(conversation):
            request = conversation[request_index][1]
            for i in range(request_index + 1, len(conversation)):
                if conversation[i][0]:
                    request += conversation[i][1]
                else:
                    break
        else:
            request = None

        if response_index < len(conversation):
            response = conversation[response_index][1]
            for i in range(response_index + 1, len(conversation)):
                if not conversation[i][0]:
                    response += conversation[i][1]
                else:
                    break
        else:
            response = None

        try:
            if request:
                request = HttpRequest.try_parse(identifier, timestamp, request)
            if response:
                response = HttpResponse.try_parse(response)
        except Exception as e:
            sys.stderr.write('Exception while parsing request/response')
            sys.stderr.write(str(e))

        sys.stdout.write(str(request) if request else 'No request found.')
        sys.stdout.write(str(response) if response else 'No response found.')

        return request, response

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

        return string

    def __repr__(self):
        string = f'*Request* {self.method} '
        if 'host' in self.headers:
            string += self.headers['host']
        string += self.url

        return string

    def body_decoded(self):
        try:
            return self.body.decode()
        except Exception as e:
            return 'Cannot decode body content: ' + str(e)

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

        return string

    def __repr__(self):
        string = f'*Response* {self.status_code} {self.status_desc}'

        return string

    def body_decoded(self):
        try:
            if 'content-encoding' in self.headers:
                content_encoding = self.headers['content-encoding'].lower()
                if 'deflate' in content_encoding:
                    return zlib.decompress(self.body, 16 + zlib.MAX_WBITS).decode()
                elif 'gzip' in content_encoding:
                    # buffer = io.BytesIO(self.body)
                    # size = buffer.readline()
                    # data = buffer.read(int(size, 16))
                    # buffer.close()
                    return gzip.decompress(self.body).decode()
                else:
                    return self.body.decode()
            else:
                return self.body.decode()
        except Exception as e:
            return 'Cannot decode body content: ' + str(e)

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
