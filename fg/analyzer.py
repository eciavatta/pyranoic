from os.path import join
from queue import Queue
from threading import Thread

import click
from scapy.all import sniff

from .constants import *
from .presets.preset import Preset
from .utils import *


class Analyzer(Thread):

    def __init__(self, project_path, service_name, preset_str, filters):
        super().__init__(daemon=True)
        self._project_path = project_path
        self._service_name = service_name
        self._preset_str = preset_str
        self._filters = filters
        self._queue = Queue()
        self._stopped = False
        self._preset = None

        self._init()

    def run(self):
        while not self._stopped:
            file_path = self._queue.get(block=True)
            sniff(offline=file_path, store=False, prn=self._preset.analyze_packet)

    def process_file(self, file_path):
        self._queue.put(file_path, block=False)

    def stop(self):
        self._stopped = True

    def get_evaluator(self):
        return self._preset

    def _init(self):
        try:
            apply_module = load_module(join(self._project_path, SERVICES_DIRNAME, self._service_name,
                                            APPLY_SCRIPT_FILENAME))
        except Exception as e:
            click.echo('Cannot load apply script file:')
            return fatal_error(str(e))

        self._preset = Preset.load_preset(self._preset_str, self._project_path, apply_module)
