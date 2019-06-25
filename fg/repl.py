import readline
import rlcompleter
import sys
import traceback
from code import InteractiveConsole
from datetime import datetime
from os import remove
from os.path import join, dirname
from queue import Queue
from tempfile import mkstemp
from time import sleep

import click

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
        self._evaluation_script_path = join(project_path, SERVICES_DIRNAME, service_name, EVALUATE_SCRIPT_FILENAME)

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
        datetime_str = timestamp2str(timestamp)
        id_str = click.style(identifier, bold=True)
        state_str = click.style(STATES_NAMES[state], fg=STATES_COLORS[state])
        additional_info_str = additional_info if additional_info else 'None'
        comment_str = comment if comment else 'None'
        log = f'[{datetime_str}] id=\'{id_str}\', evaluation={state_str}, info=\'{additional_info_str}\', ' \
            f'comment=\'{comment_str}\''

        if not self._analyzer:
            click.echo(log)
        else:
            self._queue.put(log, block=False)

    def evaluation_exception(self, exception):
        click.secho('An error occurred while evaluating a payload in the evaluation script:')
        click.secho(str(exception) + '\n', fg='red')

        if self._analyzer:
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

        self._preset = self._load_preset()
        self._preset.attach_listener(self)
        self._analyzer = Analyzer(self._project_path, self._preset, end)
        self._analyzer.set_initial_chunks(initial_chunks)
        self._analyzer.start()

        click.echo(f'Starting analyzing captures from {timestamp2str(start) if start else "now"} to '
                   f'{timestamp2str(end) if end else "manually stop"}')

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

    @command(name='find_captures', text='Display captures in a time interval')
    def _find_captures(self, start=None, end=None):
        start = parse_timestamp(start)
        end = parse_timestamp(end)
        click.echo(f'Captures from {timestamp2str(start) if start else "now"} to '
                   f'{timestamp2str(end) if end else "now"} are:')
        click.echo(self._get_chunks_between(start, end))

    @command(name='edit_eval_func', text='Edit the function to evaluate payloads')
    def _edit_evaluation_script(self, start=None, end=None):
        if self._analyzer:
            click.echo('It is not possible to modify the evaluation script when there is an active analysis.')
            return click.echo('You can stop an analysis with stop_analyze()')

        if start:
            start = parse_timestamp(start)
            end = parse_timestamp(end)
            chunks = self._get_chunks_between(start, end)
        else:
            chunks = None

        test_packets = self._load_test_packets(chunks)
        if self._edit_check_evaluation_script(test_packets):
            click.echo('Evaluation script changed.')
        else:
            click.echo('Changes to the evaluation script have been canceled.')

    @command(name='service_preset', text='Print the service preset')
    def _service_preset(self):
        click.echo(self._preset_str)

    def _get_chunks_between(self, start=None, end=None):
        chunks = list_chunks_between_timestamps(self._project_path,
                                              start if start else datetime.now().timestamp(),
                                              end if end else datetime.now().timestamp())
        return full_chunks_path(self._project_path, chunks)

    def _load_test_packets(self, chunks=None):
        if not chunks:
            chunks = [join(dirname(__file__), f'../misc/capture-{self._preset_str}.pcap')]

        test_packets = []
        for chunk in chunks:
            test_packets.extend(read_packets(chunk))

        return test_packets

    def _load_preset(self, evaluation_script=None):
        if not evaluation_script:
            evaluation_script = self._evaluation_script_path
        evaluation_module = load_module(evaluation_script)
        return Preset.load_preset(self._preset_str, self._project_path, evaluation_module)

    def _edit_check_evaluation_script(self, test_packets):
        accept = False

        tmp_path = mkstemp(suffix='.py')[1]
        with open(self._evaluation_script_path, 'r') as evaluation_file:
            with open(tmp_path, 'w') as tmp_file:
                tmp_file.write(evaluation_file.read())

        while not accept:
            click.edit(filename=tmp_path)

            try:
                preset = self._load_preset(tmp_path)
                preset.attach_listener(self)

                for packet in test_packets:
                    preset.analyze_packet(packet)
            except Exception as e:
                click.echo('An error occurred while executing the provided script:')
                click.secho(str(e), err=True, fg='red')

                if click.confirm('Do you want to retry?', default=True):
                    continue
                else:
                    remove(tmp_path)
                    return False

            accept = click.confirm('Confirm the script provided?', default=True)
            if not accept:
                retry = click.confirm('Do you want to retry?', default=True)
                if not retry:
                    remove(tmp_path)
                    return False

        with open(tmp_path, 'r') as tmp_file:
            with open(self._evaluation_script_path, 'w') as evaluation_file:
                evaluation_file.write(tmp_file.read())
        remove(tmp_path)

        return True
