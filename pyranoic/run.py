from os.path import join

from .capture import Capture
from .constants import *
from .utils import *

"""
Run command, which capture packets and save them to disk.
"""


class RunOptions(object):

    def __init__(self, daemon, path, capture_filters):
        self.is_daemon = daemon
        self.path = path
        self.capture_filters = capture_filters


def handle(options):
    capture = create_capture(options, False)

    if not options.is_daemon:
        try:
            capture.join()
        except KeyboardInterrupt:
            capture.stop()


def create_capture(options, is_live):
    config = read_config(join(options.path, PROJECT_CONFIG_FILENAME))

    if 'DEFAULT' not in config:
        fatal_error('Config file corrupted')

    file_splitting_interval = config['DEFAULT'].getint('ChunkInterval')
    disable_dns_resolution = not config['DEFAULT'].getboolean('DnsResolutionEnabled')
    tshark_path = config['DEFAULT'].get('TSharkPath')
    interface = config['DEFAULT'].get('Interface')
    filters = options.capture_filters

    capture = Capture(join(options.path, PACKETS_DIRNAME), file_splitting_interval, disable_dns_resolution, tshark_path)

    if 'REMOTE' in config:
        host = config['REMOTE'].get('Host')
        user = config['REMOTE'].get('User', None)
        port = config['REMOTE'].getint('Port', 22)
        identity_file = config['REMOTE'].get('IdentityFile', None)
        wireshark_path = config['DEFAULT'].get('WiresharkPath')

        capture.remote_capture(host, interface, user, port, identity_file, is_live, wireshark_path, filters)
    else:
        if is_live:
            fatal_error('Cannot stream packets from local interface to Wireshark. You can use wireshark directly!')
        else:
            capture.local_capture(interface, filters)

    return capture
