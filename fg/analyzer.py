from os.path import join
from queue import Queue
from threading import Thread

import click

from .constants import *
from .utils import *


class Analyzer(Thread):

    def __init__(self, service_dir, p_type, filters):
        super().__init__()
        self._service_dir = service_dir
        self._p_type = p_type
        self._filters = filters
        self._queue = Queue()
        self._stopped = False
        self._apply_module = None

    def run(self):
        self._init()

        while not self._stopped:
            self._analyze_packets(self._queue.get(block=True))

    def process_file(self, file_path):
        self._queue.put(file_path, block=False)

    def stop(self):
        self._stopped = True

    def _init(self):
        try:
            self._apply_module = load_module(join(self._service_dir, APPLY_SCRIPT_FILENAME))
        except Exception as e:
            click.echo('Cannot load apply script file:')
            fatal_error(str(e))

    def _analyze_packets(self, file_path):
        packets = read_packets(file_path, filters=self._filters)

        try:
            for packet in packets:
                print(packet)
                print(self._apply_module.apply(packet))
                print('ok no')
        except Exception as e:
            fatal_error(str(e))
