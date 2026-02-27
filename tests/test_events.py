import unittest
from datetime import datetime
from src.core.events import EventBus, EntryAdded, UserLoggedIn

class TestEventBus(unittest.TestCase):

    def setUp(self):
        self.bus = EventBus()
        self.received_events = []

    def test_subscribe_and_publish(self):

        def listener(event):
            self.received_events.append(event)

        self.bus.subscribe(EntryAdded, listener)

        event = EntryAdded(timestamp=datetime.now(), entry_id=123)
        self.bus.publish(event)

        self.assertEqual(len(self.received_events), 1)
        self.assertIs(self.received_events[0], event)
        self.assertEqual(self.received_events[0].entry_id, 123)

    def test_unsubscribe(self):

        def listener(event):
            self.received_events.append(event)

        self.bus.subscribe(UserLoggedIn, listener)
        self.bus.unsubscribe(UserLoggedIn, listener)

        event = UserLoggedIn(timestamp=datetime.now(), username="alice")
        self.bus.publish(event)

        self.assertEqual(len(self.received_events), 0)


if __name__ == "__main__":
    unittest.main()