from os.path import exists, join

import click

from .init import CONFIG_FILENAME, PACKETS_DIRNAME, SERVICES_DIRNAME


def check_valid_path(ctx, _, path):
    if (exists(join(path, CONFIG_FILENAME)) or
            exists(join(path, PACKETS_DIRNAME)) or
            exists(join(path, SERVICES_DIRNAME))):

        ctx.fail(f'Another project is present in {path}')
    return path


def check_valid_project(ctx, _, path):
    if not (exists(join(path, CONFIG_FILENAME)) and
            exists(join(path, PACKETS_DIRNAME)) and
            exists(join(path, SERVICES_DIRNAME))):

        ctx.fail(f'Invalid or corrupted project in {path}')
    return path


def fatal_error(message):
    click.echo(message, err=True)
    exit(-1)
