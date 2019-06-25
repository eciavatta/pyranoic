from os.path import isdir, join

from .constants import *
from .repl import Repl
from .utils import *

"""
Watch command, which analyze the packet flow.
"""


class WatchOptions(object):

    def __init__(self, path, service_name):
        self.path = path
        self.service_name = service_name


def handle(options):
    service_dir = service_path(options.path, options.service_name)
    if not isdir(service_path(options.path, options.service_name)):
        fatal_error(f'Cannot find service {options.service_name}')

    config = read_config(join(service_dir, SERVICE_CONFIG_FILENAME))

    repl = Repl(options.path, options.service_name, config['DEFAULT']['Preset'])
    repl.handle()
