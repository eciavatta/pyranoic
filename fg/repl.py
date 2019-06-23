from threading import Thread
import click
from datetime import datetime
from .constants import *

from queue import Queue


class Repl:

    def __init__(self, analyzer, service_name):
        super().__init__()
        self._analyzer = analyzer
        self._service_name = service_name
        self._stopped = False
        self._live_logging = True
        self._queue = Queue()

    def handle(self):
        while not self._stopped:
            if self._live_logging:
                self._logging()
            else:
                self._repl()

    def evaluation(self, identifier, timestamp, state, comment):
        if state == FILTERED_OUT:
            return

        datetime_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")
        log = f'[{datetime_str}] #{identifier} | {STATES_MAP.get(state)}'
        if comment:
            log += f' ({comment})'

        self._queue.put(log, block=False)

    def evaluation_exception(self, exception):
        print(str(exception))

    def _logging(self):
        click.echo('Entering in live logging mode. Exit with CTRL+C')
        try:
            while self._live_logging:
                log = self._queue.get(block=True)
                click.echo(log)
        except KeyboardInterrupt:
            self._live_logging = False

    def _repl(self):
        try:
            command = click.prompt(click.style(self._service_name, fg='red'), prompt_suffix='> ')
        except click.Abort:
            click.echo('\nType "exit" to quit')
            return

        if command == 'exit':
            self._stopped = True
            self._analyzer.stop()
            exit(0)
