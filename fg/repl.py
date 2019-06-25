import readline
import rlcompleter
import sys
import traceback
from code import InteractiveConsole
from datetime import datetime
from os.path import join
from queue import Queue
from time import sleep

import click
import dateparser

from fg.presets.preset import Preset
from .analyzer import Analyzer
from .constants import *
from .utils import *


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

    def __init__(self, project_path, service_name, preset_str):
        super().__init__()
        self._project_path = project_path
        self._service_name = service_name
        self._preset_str = preset_str
        self._queue = Queue()
        self._analyzer = None
        self._preset = None

        global instance
        instance = self

    def handle(self):
        sys.ps1 = click.style(self._service_name, fg='red') + '> '
        readline.set_completer(rlcompleter.Completer(commands).complete)
        readline.parse_and_bind("tab: complete")
        banner = 'Welcome to analysis board. Use commands() to list all the possible commands. ' \
                 'Use info(command) to view the documentation of specific command. Have fun!'
        InteractiveConsole(locals=commands).interact(banner=banner, exitmsg='')

        if self._analyzer:
            commands['stop_analyze']()

    def evaluation(self, identifier, timestamp, state, additional_info = None, comment = None):
        if state == FILTERED_OUT:
            return

        datetime_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")
        id_str = click.style(identifier, bold=True)
        state_str = click.style(STATES_NAMES[state], fg=STATES_COLORS[state])
        additional_info_str = additional_info if additional_info else 'None'
        comment_str = comment if comment else 'None'
        log = f'[{datetime_str}] id=\'{id_str}\', evaluation={state_str}, info=\'{additional_info_str}\', ' \
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
            return click.echo('Identifier must be a string with length greater than zero', err=True)

        self._preset.describe(identifier, output)

    @command(name='generate_exploit', text='Generate exploit from a payload')
    def _generate_exploit(self, identifier, output=None):
        if type(identifier) is not str or not len(identifier) > 0:
            return click.echo('Identifier must be a string with length greater than zero', err=True)

        self._preset.generate_exploit(identifier, output)

    @command(name='analyze', text='Start analyze captures')
    def _analyze(self, start=None, end=None):
        if self._analyzer:
            click.echo('Stop previous analysis before starting another')
            return

        start = parse_timestamp(start)
        end = parse_timestamp(end)
        initial_chunks = self._get_chunks_between(start, end)

        if initial_chunks is None:
            return click.echo('Cannot find captures in the range indicated.')

        evaluation_script_path = join(self._project_path, SERVICES_DIRNAME, self._service_name, APPLY_SCRIPT_FILENAME)
        evaluation_module = load_module(evaluation_script_path)
        self._preset = Preset.load_preset(self._preset_str, self._project_path, evaluation_module)
        self._preset.attach_listener(self)
        self._analyzer = Analyzer(self._project_path, self._preset, end)
        self._analyzer.set_initial_chunks(initial_chunks)
        self._analyzer.start()

        click.echo('Starting analyzing captures..')

    @command(name='stop_analyze', text='Stop analyze captures')
    def _stop_analyze(self):
        if not self._analyzer:
            return click.echo('There is no active analysis process.', err=True)

        self._analyzer.stop()
        self._analyzer = None
        self._preset = None

        sleep(1)
        click.echo('Analyze process stopped.')

    @command(name='current_capture', text='Display the current capture file path')
    def _current_capture(self):
        capture_path = self._get_chunks_between()
        if len(capture_path) == 1:
            click.echo(capture_path[0])
        else:
            click.echo('No capture found.')

    def _get_chunks_between(self, start=None, end=None):
        return list_chunks_between_timestamps(self._project_path,
                                              start if start else datetime.now().timestamp(),
                                              end if end else datetime.now().timestamp())
