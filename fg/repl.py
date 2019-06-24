from datetime import datetime
from queue import Queue
from code import InteractiveConsole
import sys
import traceback

import click

from .constants import *


def print_commands():
    click.echo('List of available commands:')
    for name, desc in descriptions.items():
        click.echo(f'\t{name}: {desc}')


def command(name, text, is_method=True):

    def decorator(function):
        def wrapper(*args, **kwargs):
            if is_method:
                function(instance, *args, **kwargs)
            else:
                function(*args, **kwargs)

        global descriptions
        global commands

        if 'descriptions' not in globals():
            descriptions = {}
        if 'commands' not in globals():
            commands = {
                'commands': print_commands
            }

        commands[name] = wrapper
        descriptions[name] = text

        return wrapper

    return decorator


class Repl:

    def __init__(self, analyzer, service_name):
        super().__init__()
        self._analyzer = analyzer
        self._service_name = service_name
        self._queue = Queue()

        global instance
        instance = self

    def handle(self):
        sys.ps1 = click.style(self._service_name, fg='red') + '> '
        commands['logs']()
        InteractiveConsole(locals=commands).interact(banner='', exitmsg='')
        self._analyzer.stop()
        exit(0)

    def evaluation(self, identifier, timestamp, state, additional_info = None, comment = None):
        if state == FILTERED_OUT:
            return

        datetime_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")
        id_str = click.style(identifier, bold=True)
        state_str = click.style(STATES_NAMES[state], fg=STATES_COLORS[state])
        additional_info_str = additional_info if additional_info else 'None'
        comment_str = comment if comment else 'None'
        log = f'[{datetime_str}] id=\'{id_str}\', | evaluation={state_str}, info=\'{additional_info_str}\', ' \
            f'comment=\'{comment_str}\''

        self._queue.put(log, block=False)

    def evaluation_exception(self, exception):
        print(exception)
        traceback.print_stack()

    @command(name='logs', text='Enter in live logging mode and display evaluations on screen')
    def _logs(self):
        click.echo('Entering in live logging mode. Exit with CTRL+C')
        try:
            while True:
                log = self._queue.get(block=True)
                click.echo(log)
        except KeyboardInterrupt:
            return

    @command(name='describe', text='View details of a payload on screen')
    def _describe(self, identifier, output=None):
        if type(identifier) is not str or not len(identifier) > 0:
            click.echo('Identifier must be a string with length greater than zero', err=True)
            return

        self._analyzer.get_evaluator().describe(identifier, output)
