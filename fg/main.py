import click

"""
Entry point of the tool.
"""


@click.group()
def cli():
    pass


@cli.command()
@click.option('--interface', '-i', required=True)
@click.option('--remote', '-r', is_flag=True, default=False, show_default=True)
@click.option('--host', '-h')
@click.option('--user', '-u')
@click.option('--port', '-p', default=22, show_default=True, type=int)
@click.option('--identity-file')
@click.option('--daemon', '-d', is_flag=True, default=False, show_default=True)
@click.option('--interval', default=60, show_default=True, type=int)
@click.option('--dns-resolution', is_flag=True, default=False, show_default=True)
@click.option('--tshark-path', default='/usr/bin/tshark', show_default=True)
@click.option('--wireshark-path', default='/usr/bin/wireshark', show_default=True)
@click.argument('path', default='.')
def run(interface, remote, host, user, port, identity_file, daemon, interval, dns_resolution, tshark_path,
        wireshark_path, path):
    """Start capturing packets."""

    from .run import RunCommand, handle

    handle(RunCommand(
        interface, remote, host, user, port, identity_file, daemon, interval, dns_resolution, tshark_path,
        wireshark_path, path
    ))


if __name__ == "__main__":
    cli()
