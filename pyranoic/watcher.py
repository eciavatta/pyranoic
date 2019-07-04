from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer


class Watcher:
    def __init__(self, path, handler, recursive=False):
        self._path = path
        self._handler = handler
        self._recursive = recursive
        self._event_observer = Observer()

    def start(self):
        self._event_observer.schedule(
            self._handler,
            self._path,
            self._recursive
        )
        self._event_observer.start()

    def join(self):
        self._event_observer.join()

    def stop(self):
        self._event_observer.stop()


class WatcherEventHandler(FileSystemEventHandler):

    def __init__(self, on_any_event=None, on_created=None, on_deleted=None, on_modified=None, on_moved=None):
        super().__init__()
        self._on_any_event = on_any_event
        self._on_created = on_created
        self._on_deleted = on_deleted
        self._on_modified = on_modified
        self._on_moved = on_moved

    def on_any_event(self, event):
        if self._on_any_event is not None:
            self._on_any_event(event.src_path)

    def on_created(self, event):
        if self._on_created is not None:
            self._on_created(event.src_path)

    def on_deleted(self, event):
        if self._on_deleted is not None:
            self._on_deleted(event.src_path)

    def on_modified(self, event):
        if self._on_modified is not None:
            self._on_modified(event.src_path)

    def on_moved(self, event):
        if self._on_moved is not None:
            self._on_moved(event.src_path)
