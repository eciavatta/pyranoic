import os
from configparser import ConfigParser
from os.path import exists, join, dirname, isdir
from shutil import rmtree
from tempfile import mkstemp

import click

from .constants import *
from .utils import *

"""
Run command, which capture packets and save them to disk.
"""


class ServiceOptions(object):

    def __init__(self, inline, name, port, p_type, path, display_filters):
        self.inline = inline
        self.name = name
        self.port = port
        self.p_type = p_type
        self.path = path
        self.display_filters = display_filters


def handle_create(options):
    """Handle creation of new service."""

    service_dir = service_path(options.path, options.name)
    if exists(service_dir):
        fatal_error(f'Another service with name {options.name} is present')

    tmp_fd, tmp_path = mkstemp(suffix='.py')

    with open(join(dirname(__file__), f'../misc/apply-{options.p_type}.py'), 'r') as default_apply_file:
        with os.fdopen(tmp_fd, 'w') as tmp_file:
            tmp_file.write(default_apply_file.read())

    if not options.inline and not _edit_apply_file(options.p_type, tmp_path):
        os.remove(tmp_path)
        exit(0)

    apply_script_path = join(service_dir, APPLY_SCRIPT_FILENAME)
    os.mkdir(service_dir)
    with open(tmp_path, 'r') as tmp_file:
        with open(apply_script_path, 'w') as apply_script_file:
            apply_script_file.write(tmp_file.read())

    config = ConfigParser()
    if options.port is not None:
        config['DEFAULT']['DisplayFilters'] = f'"tcp.port == {options.port}"'
    config['DEFAULT']['Type'] = options.p_type
    if options.display_filters is not None:
        config['DEFAULT']['DisplayFilters'] = f'"{options.display_filters}"'

    write_config(config, join(service_dir, SERVICE_CONFIG_FILENAME))


def handle_edit(options):
    """Handle modification of existing service."""

    service_dir = service_path(options.path, options.name)
    if not isdir(service_dir):
        fatal_error(f'Cannot find service {options.name}')

    config_path = join(service_dir, SERVICE_CONFIG_FILENAME)
    config = read_config(config_path)
    p_type = options.p_type

    if options.port is not None:
        config['DEFAULT']['DisplayFilters'] = f'"tcp.port == {options.port}"'
    if p_type is not None:
        config['DEFAULT']['Type'] = p_type
    else:
        p_type = config['DEFAULT'].get('Type')
    if options.display_filters is not None:
        config['DEFAULT']['DisplayFilters'] = f'"{options.display_filters}"'

    write_config(config, config_path)

    if not options.inline:
        _edit_apply_file(p_type, join(service_dir, APPLY_SCRIPT_FILENAME))


def handle_remove(options):
    """Handle removal of existing service."""

    service_dir = service_path(options.path, options.name)
    if not isdir(service_dir):
        fatal_error(f'Cannot find service {options.name}')

    rmtree(service_dir)


def handle_list(options):
    """Handle listing of all services."""

    services_path = join(options.path, SERVICES_DIRNAME)
    services_names = [name for name in os.listdir(services_path) if isdir(join(services_path, name))]

    if len(services_names) == 0:
        click.echo('No service present yet')
    else:
        click.echo('List of services created:')
    for service_name in services_names:
        service_dir = service_path(options.path, service_name)
        config = read_config(join(service_dir, SERVICE_CONFIG_FILENAME))["DEFAULT"]
        click.echo(f'\t- {service_name} [type = "{config.get("Type")}", filters = {config.get("DisplayFilters")}]')


def _edit_apply_file(p_type, apply_file_path):
    test_packets = read_packets(join(dirname(__file__), f'../misc/capture-{p_type}.pcap'))
    accept = False

    while not accept:
        click.edit(filename=apply_file_path)
        results = []

        try:
            apply_module = load_module(apply_file_path)

            for packet in test_packets:
                result = apply_module.apply(packet)
                if result not in [NORMAL, SUSPICIOUS, MARKED, FILTER_OUT]:
                    raise ValueError('Script returns an invalid value')
                results.append(result)
        except Exception as e:
            click.echo('An error occurred while executing the provided script:')
            click.secho(str(e), err=True, fg='red')

            if click.confirm('Do you want to retry?', default=True):
                continue
            else:
                return False

        click.echo('Script results with test packages:')
        click.echo(f'Normal: {sum(x == NORMAL for x in results)}')
        click.echo(f'Suspicious: {sum(x == SUSPICIOUS for x in results)}')
        click.echo(f'Marked: {sum(x == MARKED for x in results)}')
        click.echo(f'FilterOut: {sum(x == FILTER_OUT for x in results)}')

        accept = click.confirm('Confirm the script provided?', default=True)

    return True
