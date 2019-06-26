import re
from datetime import datetime
from os.path import join
from queue import Queue, Empty
from threading import Thread
from time import sleep

from scapy.all import sniff

from .watcher import WatcherEventHandler, Watcher
from .constants import *
from .utils import *


class Analyzer(Thread):

    def __init__(self, project_path, preset, stop_timestamp):
        super().__init__(daemon=True)
        self._project_path = project_path
        self._preset = preset
        self._stop_timestamp = stop_timestamp
        self._queue = Queue()
        self._stopped = False
        self._pcap_regex_compiled = re.compile(PCAP_REGEX_PATTERN)
        self._last_chunk = None  # used to track the last chunk completed to analyze
        self._watcher = None

    def run(self):
        handler = WatcherEventHandler(on_created=self._process_file)
        self._watcher = Watcher(join(self._project_path, PACKETS_DIRNAME), handler)
        self._watcher.start()

        while not self._stopped and (not self._stop_timestamp or datetime.now().timestamp() < self._stop_timestamp):
            try:
                file_path = self._queue.get(block=True, timeout=1)
            except Empty:
                continue

            sniff(offline=file_path, store=False, prn=self._preset.filter_analyze_packet)

    def stop(self):
        if self._watcher:
            self._watcher.stop()
        self._stopped = True

    def set_initial_chunks(self, chunks):
        for chunk in chunks:
            self._process_file(chunk, False)

    def _process_file(self, capture_path, do_sleep=True):
        if file_name_match(capture_path, self._pcap_regex_compiled):
            tmp = self._last_chunk
            self._last_chunk = capture_path
            if tmp:
                if do_sleep:
                    sleep(1)  # precaution (wait tshark close file descriptor for old chunk)
                self._queue.put(tmp, block=False)
        else:
            raise OSError('An invalid file is created on packets directory.')
