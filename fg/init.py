from configparser import ConfigParser
from os import mkdir
from os.path import exists, join

from .constants import *
from .utils import *

"""
Init command, which create and prepare workspace.
"""


class InitOptions(object):

    def __init__(self, interface, remote, host, port, user, identity_file, interval, dns_resolution,
                 tshark_path, wireshark_path, path):
        self.interface = interface
        self.is_remote = remote
        self.host = host
        self.user = user
        self.port = port
        self.identity_file = identity_file
        self.interval = interval
        self.dns_resolution_enabled = dns_resolution
        self.tshark_path = tshark_path
        self.wireshark_path = wireshark_path
        self.path = path


def handle(options):
    config = ConfigParser()
    config['DEFAULT'] = {
        'Interface': options.interface,
        'ChunkInterval': options.interval,
        'DnsResolutionEnabled': options.dns_resolution_enabled,
        'TSharkPath': options.tshark_path,
        'WiresharkPath': options.wireshark_path
    }

    if options.is_remote:
        tmp = {
            'Host': options.host,
            'Port': options.port
        }
        if options.user is not None:
            tmp['User'] = options.user
        if options.identity_file is not None:
            tmp['IdentityFile'] = options.identity_file

        config['REMOTE'] = tmp

    if not exists(options.path):
        mkdir(options.path)

    mkdir(join(options.path, PACKETS_DIRNAME))
    mkdir(join(options.path, SERVICES_DIRNAME))

    write_config(config, join(options.path, PROJECT_CONFIG_FILENAME))
