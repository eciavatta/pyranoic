from os.path import isdir, join, splitext

import click

from .analyzer import Analyzer
from .constants import *
from .utils import *
from .watcher import Watcher, WatcherEventHandler

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
        fatal_error(f'Cannot find service {options.name}')

    config = read_config(join(service_dir, SERVICE_CONFIG_FILENAME))
    config['DEFAULT'].get('DisplayFilters')
    analyzer = Analyzer(service_dir, config['DEFAULT'].get('Type'), config['DEFAULT'].get('DisplayFilters'))
    global _analyze_callback
    _analyze_callback = analyzer.process_file
    analyzer.start()

    handler = WatcherEventHandler(on_created=_watcher_filter_callback)
    watcher = Watcher(join(options.path, PACKETS_DIRNAME), handler)
    watcher.start()

    watcher.join()


def _watcher_filter_callback(capture_path):
    capture_name, capture_extension = splitext(CAPTURE_FILENAME)
    regex_pattern = rf"^{capture_name}_\d{{5}}_\d{{14}}{capture_extension}$"
    if file_name_match(capture_path, regex_pattern) is not None:
        _analyze_callback(capture_path)
    else:
        click.echo('An invalid file is created on packets directory.', err=True)
