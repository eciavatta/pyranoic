from os import getcwd

import click

from .utils import check_valid_path, check_valid_project

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

    from .init import InitConfig, handle

    if interface is None:
        if inline:
            ctx.fail('Interface parameter is required')
        else:
            interface = click.prompt('Interface to capture')
    if remote is None:
        if inline:
            remote = False
        else:
            remote = click.prompt('Is remote interface', type=click.Choice(['yes', 'no']), prompt_suffix='? ') == 'yes'
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

    handle(InitConfig(
        interface, remote, host, port, user, identity_file, interval, dns_resolution, tshark_path, wireshark_path, path
    ))


@cli.command()
@click.option('--daemon', '-d', is_flag=True, default=False, show_default=True)
@click.option('--path', default=getcwd(), required=True, callback=check_valid_project, show_default=True)
@click.argument('capture-filters', nargs=-1)
def run(daemon, path, capture_filters):
    """Start capturing packets."""

    from .run import RunConfig, handle

    handle(RunConfig(daemon, path, capture_filters))


@cli.command()
@click.option('--path', default=getcwd(), required=True, callback=check_valid_project, show_default=True)
@click.argument('capture-filters', nargs=-1)
def ws_live(path, capture_filters):
    """Start capturing packets and displaying on Wireshark."""

    from .run import RunConfig, create_capture

    create_capture(RunConfig(True, path, capture_filters), True)


if __name__ == "__main__":
    cli()
