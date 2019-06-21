import click

from .main import cli

"""
Init command, which create and prepare workspace.
"""


@cli.command()
@click.option('--inline', help='configure project inline')
@click.option('-l', '--local', help='capture packet on local host')
@click.option('--remote', help='capture packet on remote host')
@click.argument('path', required=False)
def init():
    """Create an empty project and configure it."""