from configparser import ConfigParser
from os.path import join

from .capture import Capture
from .init import CONFIG_FILENAME, PACKETS_DIRNAME
from .utils import fatal_error

"""
Run command, which capture packets and save them to disk.
"""


class RunConfig(object):

    def __init__(self, daemon, path, capture_filters):
        self.is_daemon = daemon
        self.path = path
        self.capture_filters = capture_filters


def handle(config):
    conf = ConfigParser()
    conf.read(CONFIG_FILENAME)

    if 'DEFAULT' not in conf:
        fatal_error('Config file corrupted')

    file_splitting_interval = conf['DEFAULT'].getint('ChunkInterval')
    disable_dns_resolution = not conf['DEFAULT'].getboolean('DnsResolutionEnabled')
    tshark_path = conf['DEFAULT'].get('TSharkPath')
    interface = conf['DEFAULT'].get('Interface')
    filters = config.capture_filters

    capture = Capture(join(config.path, PACKETS_DIRNAME), file_splitting_interval, disable_dns_resolution, tshark_path)

    if 'REMOTE' in conf:
        host = conf['REMOTE'].get('Host')
        user = conf['REMOTE'].get('User', None)
        port = conf['REMOTE'].getint('Port', 22)
        identity_file = conf['REMOTE'].get('IdentityFile', None)
        wireshark_path = conf['DEFAULT'].get('WiresharkPath')

        capture.remote_capture(host, interface, user, port, identity_file, False, wireshark_path, filters)
    else:
        capture.local_capture(interface, filters)

    if not config.is_daemon:
        try:
            capture.join()
        except KeyboardInterrupt:
            capture.stop()
