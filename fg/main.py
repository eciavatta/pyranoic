from os import getcwd

import click

from .utils import *

"""
Entry point of the tool.
"""


@click.group()
def cli():
    pass


@cli.command()
@click.pass_context
@click.option('--inline', is_flag=True, default=False)
@click.option('--interface', '-i')
@click.option('--remote', '-r', is_flag=True, default=None, show_default=True)
@click.option('--host', '-h')
@click.option('--port', '-p', default=22, show_default=True, type=int)
@click.option('--user', '-u')
@click.option('--identity-file')
@click.option('--interval', default=60, show_default=True, type=int)
@click.option('--dns-resolution', is_flag=True, default=False, show_default=True)
@click.option('--tshark-path', default='/usr/bin/tshark', show_default=True)
@click.option('--wireshark-path', default='/usr/bin/wireshark', show_default=True)
@click.argument('path', default=getcwd(), required=True, callback=check_valid_path)
def init(ctx, inline, interface, remote, host, port, user, identity_file, interval, dns_resolution, tshark_path,
         wireshark_path, path):
    """Create an empty project and configure it."""

    from .init import InitOptions, handle

    if interface is None:
        if inline:
            ctx.fail('Interface parameter is required')
        else:
            interface = click.prompt('Interface to capture')
    if remote is None:
        if inline:
            remote = False
        else:
            remote = click.confirm('Is remote interface', default=False)
    if remote:
        if host is None:
            if inline:
                ctx.fail('Host parameter is required for remote capture')
            else:
                host = click.prompt('Remote host')
        if not inline and port == 22:
            port = click.prompt('Remote port', default=22, show_default=True, type=int)
        if not inline and user is None:
            user = click.prompt('User', default='None', show_default=True)
            user = None if user == 'None' else user

    handle(InitOptions(
        interface, remote, host, port, user, identity_file, interval, dns_resolution, tshark_path, wireshark_path, path
    ))


@cli.command()
@click.option('--daemon', '-d', is_flag=True, default=False, show_default=True)
@click.option('--path', default=getcwd(), required=True, callback=check_valid_project, show_default=True)
@click.option('--capture-filters')
def run(daemon, path, capture_filters):
    """Start capturing packets."""

    from .run import RunOptions, handle

    handle(RunOptions(daemon, path, capture_filters))


@cli.command()
@click.pass_context
@click.option('--create', '-c', is_flag=True, default=False)
@click.option('--rm', is_flag=True, default=False)
@click.option('--preset', type=click.Choice(['tcp', 'http', 'raw']), default=None)
@click.option('--path', default=getcwd(), required=True, callback=check_valid_project, show_default=True)
@click.argument('service-name', nargs=-1)
def service(ctx, create, rm, preset, path, service_name):
    """Display, create or remove services."""

    from .service import ServiceOptions, handle_list, handle_create, handle_remove
    from .constants import AVAILABLE_PRESETS

    if create or rm:
        if not service_name:
            ctx.fail('Argument SERVICE_NAME is required')
        elif len(service_name) > 1:
            ctx.fail('Only one argument for SERVICE_NAME is required')
        else:
            service_name = service_name[0]

    if create:
        if not preset:
            preset = click.prompt('Service preset', type=click.Choice(AVAILABLE_PRESETS))

    options = ServiceOptions(service_name, preset, path)

    if create:
        handle_create(options)
    elif rm:
        handle_remove(options)
    else:
        handle_list(options)


@cli.command()
@click.option('--path', default=getcwd(), required=True, callback=check_valid_project, show_default=True)
@click.argument('service-name', nargs=1)
def watch(path, service_name):
    """Watch a service and analyze the packet flow"""

    from .watch import WatchOptions, handle

    handle(WatchOptions(path, service_name))


@cli.command()
@click.option('--path', default=getcwd(), required=True, callback=check_valid_project, show_default=True)
@click.argument('capture-filters', nargs=-1)
def ws_live(path, capture_filters):
    """Start capturing packets and displaying on Wireshark."""

    from .run import RunOptions, create_capture

    create_capture(RunOptions(True, path, capture_filters), True)


if __name__ == "__main__":
    cli()
