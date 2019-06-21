from .capture import Capture

"""
Run command, which capture packets and save them to disk.
"""


class RunCommand(object):

    def __init__(self, interface, remote, host, user, port, identity_file, daemon, interval, dns_resolution,
                 tshark_path, wireshark_path, path):
        self.interface = interface
        self.is_remote = remote
        self.host = host
        self.user = user
        self.port = port
        self.identity_file = identity_file
        self.is_daemon = daemon
        self.interval = interval
        self.dns_resolution_enabled = dns_resolution
        self.tshark_path = tshark_path
        self.wireshark_path = wireshark_path
        self.path = path


def handle(command):
    capture = Capture(capture_dir='/tmp', file_splitting_interval=command.interval,
                      disable_dns_resolution=not command.dns_resolution_enabled, tshark_path=command.tshark_path)

    if command.is_remote:
        output = capture.remote_capture(command.host, command.interface, command.user, command.port, 'password',
                                        command.identity_file, live=False, wireshark_path=command.wireshark_path)
    else:
        output = capture.local_capture(command.interface)

    print(output.decode("utf-8"))

    if not command.is_daemon:
        try:
            capture.join()
        except KeyboardInterrupt:
            capture.stop()
