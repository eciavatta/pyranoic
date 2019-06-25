from ..constants import *
from ..utils import fatal_error


class Preset:

    def __init__(self, project_path, apply_module):
        self._project_path = project_path
        self._apply_module = apply_module
        self._listener = None

    @staticmethod
    def load_preset(preset_str, project_path, apply_module):
        if preset_str == 'raw':
            from .raw_preset import RawPreset
            return RawPreset(project_path, apply_module)
        elif preset_str == 'tcp':
            from .tcp_preset import TcpPreset
            return TcpPreset(project_path, apply_module)
        elif preset_str == 'http':
            from .http_preset import HttpPreset
            return HttpPreset(project_path, apply_module)
        else:
            fatal_error(f'Invalid preset: {preset_str}')

    def evaluate_and_submit(self, identifier, timestamp, payload, additional_info=None):
        try:
            evaluation = self._apply_module.apply(payload)

            if (type(evaluation) is not int and type(evaluation) is not tuple) or (
                type(evaluation) is tuple and (
                    len(evaluation) != 2 or type(evaluation[0]) != int or type(evaluation[1]) != str)):
                raise TypeError('Invalid return type of evaluate function (valid types: State or <State, Comment>)')

            state = evaluation if type(evaluation) is int else evaluation[0]
            comment = None if type(evaluation) is int else evaluation[1]

            if state not in [NORMAL, SUSPICIOUS, MARKED, FILTERED_OUT]:
                raise ValueError('Invalid return value in apply script (invalid state)')
        except Exception as e:
            return self._listener.evaluation_exception(e)

        self._listener.evaluation(identifier, timestamp, state, additional_info, comment)

    def attach_listener(self, listener):
        self._listener = listener

    def analyze_packet(self, packet):
        pass

    def describe(self, identifier, out_file):
        pass

    def generate_exploit(self, identifier, out_file):
        pass
