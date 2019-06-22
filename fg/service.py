import os
from configparser import ConfigParser
from os.path import dirname, isdir
from tempfile import mkstemp

from .constants import *
from .utils import *

"""
Run command, which capture packets and save them to disk.
"""

CONFIG_FILENAME = 'service.conf'
APPLY_SCRIPT_FILENAME = 'apply-script.py'


class ServiceOptions(object):

    def __init__(self, inline, name, port, p_type, path, display_filters):
        self.inline = inline
        self.name = name
        self.port = port
        self.p_type = p_type
        self.path = path
        self.display_filters = display_filters


def handle_create(options):
    service_dir = service_path(options.path, options.name)
    if exists(service_dir):
        fatal_error(f'Another service with name {options.name} is present')

    tmp_fd, tmp_path = mkstemp(suffix='.py')

    with open(join(dirname(__file__), f'../misc/apply-{options.p_type}.py'), 'r') as apply_file:
        with os.fdopen(tmp_fd, 'w') as tmp_file:
            tmp_file.write(apply_file.read())

    test_packets = read_packets(join(dirname(__file__), f'../misc/capture-{options.p_type}.pcap'))

    accept = False
    while not accept and not options.inline:
        click.edit(filename=tmp_path)
        apply_module = load_module(tmp_path)

        results = []

        try:
            for packet in test_packets:
                result = apply_module.apply_raw(packet)
                if result not in [NORMAL, SUSPICIOUS, MARKED, FILTER_OUT]:
                    raise ValueError('Script returns an invalid value')
                results.append(apply_module.apply_raw(packet))
        except Exception as e:
            click.echo('An error occurred while executing the provided script:')
            click.secho(str(e), err=True, fg='red')

            if click.confirm('Do you want to retry?', default=True):
                continue
            else:
                os.remove(tmp_path)
                exit(0)

        click.echo('Script results with test packages:')
        click.echo(f'Normal: {sum(x == NORMAL for x in results)}')
        click.echo(f'Suspicious: {sum(x == SUSPICIOUS for x in results)}')
        click.echo(f'Marked: {sum(x == MARKED for x in results)}')
        click.echo(f'FilterOut: {sum(x == FILTER_OUT for x in results)}')

        accept = click.confirm('Confirm the script provided?', default=True)

    apply_script_path = join(service_dir, APPLY_SCRIPT_FILENAME)
    os.mkdir(service_dir)
    with open(tmp_path, 'r') as tmp_file:
        with open(apply_script_path, 'w') as apply_script_file:
            apply_script_file.write(tmp_file.read())

    config = ConfigParser()
    if options.port is not None:
        config['DEFAULT']['DisplayFilters'] = f'tcp.port == {options.port}'
    config['DEFAULT']['Type'] = options.p_type
    if options.display_filters:
        config['DEFAULT']['DisplayFilters'] = ''.join(options.display_filters)

    with open(join(service_dir, CONFIG_FILENAME), 'w') as configfile:
        config.write(configfile)


def handle_edit(options):
    service_dir = service_path(options.path, options.name)
    if not isdir(service_dir):
        fatal_error(f'Cannot find service {options.name}')






def handle_remove(options):
    print()


def handle_list(options):
    print()

