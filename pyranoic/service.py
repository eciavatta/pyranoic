import os
from configparser import ConfigParser
from os import mkdir
from os.path import exists, join, dirname, isdir
from shutil import rmtree

import click

from .constants import *
from .utils import *

"""
Run command, which capture packets and save them to disk.
"""


class ServiceOptions(object):

    def __init__(self, name, preset, path):
        self.name = name
        self.preset = preset
        self.path = path


def handle_create(options):
    """Handle creation of new service."""

    service_dir = service_path(options.path, options.name)
    if exists(service_dir):
        fatal_error(f'Another service with name {options.name} is present')

    mkdir(service_dir)
    with open(join(dirname(__file__), f'misc/evaluate-{options.preset}.py'), 'r') as default_eval_file:
        with open(join(service_dir, EVALUATE_SCRIPT_FILENAME), 'w+') as eval_file:
            eval_file.write(default_eval_file.read())

    config = ConfigParser()
    config['DEFAULT']['Preset'] = options.preset

    write_config(config, join(service_dir, SERVICE_CONFIG_FILENAME))


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
        click.echo(f'\t- {service_name} [preset= "{config.get("Preset")}"]')
