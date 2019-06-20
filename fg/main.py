
"""
Entry point of the tool.
"""

import click
from .capture import Capture

@click.group()
def cli():
    pass


@cli.command()
@click.option('--inline', help='configure project inline')
@click.option('-l', '--local', help='capture packet on local host')
@click.option('--remote', help='capture packet on remote host')
@click.argument('path', required=False)
def init():
    """Create an empty project and configure it."""


@cli.command()
def run():
    """Start capturing packets."""
    capture = Capture(capture_dir='/tmp')
    capture.local_chunked_capture('wlp2s0')


if __name__ == "__main__":
    cli()