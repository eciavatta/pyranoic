import re
from os.path import isdir, join
from time import sleep

import click

from .analyzer import Analyzer
from .constants import *
from .utils import *
from .watcher import Watcher, WatcherEventHandler
from .repl import Repl

"""
Watch command, which analyze the packet flow.
"""


class WatchOptions(object):

    def __init__(self, path, service_name):
        self.path = path
        self.service_name = service_name


def handle(options):
    service_dir = service_path(options.path, options.service_name)
    if not isdir(service_dir):
        fatal_error(f'Cannot find service {options.service_name}')

    config = read_config(join(service_dir, SERVICE_CONFIG_FILENAME))
    config['DEFAULT'].get('DisplayFilters')
    analyzer = Analyzer(service_dir, config['DEFAULT'].get('Preset'), config['DEFAULT'].get('DisplayFilters'))
    global _analyze_callback
    global _pcap_regex_compiled
    global _last_chunk  # used to track the last chunk completed to analyze

    _analyze_callback = analyzer.process_file
    _pcap_regex_compiled = re.compile(PCAP_REGEX_PATTERN)

    chunks = list_packets_chunks(options.path)  # the first time take the newest in the packets dir
    if len(chunks) > 0:  # .. if exists
        _last_chunk = join(options.path, PACKETS_DIRNAME, list_packets_chunks(options.path)[-1])

    handler = WatcherEventHandler(on_created=_watcher_filter_callback)
    watcher = Watcher(join(options.path, PACKETS_DIRNAME), handler)
    watcher.start()

    repl = Repl(analyzer, options.service_name)
    analyzer.get_evaluator().attach_listener(repl)
    analyzer.start()
    repl.handle()


def _watcher_filter_callback(capture_path):
    if file_name_match(capture_path, _pcap_regex_compiled):
        global _last_chunk

        tmp = _last_chunk
        _last_chunk = capture_path
        if tmp:
            sleep(3)  # precaution (wait tshark close file descriptor for old chunk)
            _analyze_callback(tmp)
    else:
        click.echo('An invalid file is created on packets directory.', err=True)
