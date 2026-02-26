from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Dict, List, Type
import threading


@dataclass
class Event:
    timestamp: datetime

@dataclass
class EntryAdded(Event):
    entry_id: int

@dataclass
class EntryUpdated(Event):
    entry_id: int

@dataclass
class EntryDeleted(Event):
    entry_id: int

@dataclass
class UserLoggedIn(Event):
    username: str

@dataclass
class UserLoggedOut(Event):
    username: str

@dataclass
class ClipboardCopied(Event):
    entry_id: int

@dataclass
class ClipboardCleared(Event):
    pass

class EventBus:
    def __init__(self):
        self._subscribers: Dict[Type[Event], List[Callable]] = {}
        self._lock = threading.Lock()

    def subscribe(self, event_type: Type[Event], handler: Callable):
        with self._lock:
            if event_type not in self._subscribers:
                self._subscribers[event_type] = []
            self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: Type[Event], handler: Callable):
        with self._lock:
            if event_type in self._subscribers:
                if handler in self._subscribers[event_type]:
                    self._subscribers[event_type].remove(handler)

    def publish(self, event: Event):
        with self._lock:
            handlers = self._subscribers.get(type(event), []).copy()

        for handler in handlers:
            handler(event)

event_bus = EventBus()