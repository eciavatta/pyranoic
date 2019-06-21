from configparser import ConfigParser

from os import mkdir
from os.path import exists, join

"""
Init command, which create and prepare workspace.
"""

CONFIG_FILENAME = 'project.conf'
PACKETS_DIRNAME = 'packets'
SERVICES_DIRNAME = 'services'


class InitConfig(object):

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


def handle(config):
    conf = ConfigParser()
    conf['DEFAULT'] = {
        'Interface': config.interface,
        'ChunkInterval': config.interval,
        'DnsResolutionEnabled': config.dns_resolution_enabled,
        'TSharkPath': config.tshark_path,
        'WiresharkPath': config.wireshark_path
    }

    if config.is_remote:
        tmp = {
            'Host': config.host,
            'Port': config.port
        }
        if config.user is not None:
            tmp['User'] = config.user
        if config.identity_file is not None:
            tmp['IdentityFile'] = config.identity_file

        conf['REMOTE'] = tmp

    if not exists(config.path):
        mkdir(config.path)

    mkdir(join(config.path, PACKETS_DIRNAME))
    mkdir(join(config.path, SERVICES_DIRNAME))

    with open(join(config.path, CONFIG_FILENAME), 'w') as configfile:
        conf.write(configfile)
