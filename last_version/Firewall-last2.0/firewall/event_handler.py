import asyncio


class EventHandler:
    def __init__(self):
        self.event_handlers = {}
        self.observers = {}

    def register_event_handler(self, event_type, handler):
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []

        self.event_handlers[event_type].append(handler)

    def unregister_event_handler(self, event_type, handler):
        if event_type in self.event_handlers:
            handlers = self.event_handlers[event_type]
            if handler in handlers:
                handlers.remove(handler)

    def subscribe(self, event_type, observer):
        if event_type not in self.observers:
            self.observers[event_type] = []

        self.observers[event_type].append(observer)

    def unsubscribe(self, event_type, observer):
        if event_type in self.observers:
            observers = self.observers[event_type]
            if observer in observers:
                observers.remove(observer)

    def handle_event(self, event_type, event_data):
        if event_type in self.event_handlers:
            handlers = self.event_handlers[event_type]
            for handler in handlers:
                handler(event_data)

        if event_type in self.observers:
            observers = self.observers[event_type]
            for observer in observers:
                observer.notify(event_type, event_data)

    async def handle_event_async(self, event_type, event_data):
        if event_type in self.event_handlers:
            handlers = self.event_handlers[event_type]
            await asyncio.gather(*[self._execute_handler_async(handler, event_data) for handler in handlers])

        if event_type in self.observers:
            observers = self.observers[event_type]
            await asyncio.gather(*[self._execute_observer_async(observer, event_type, event_data) for observer in observers])

    async def _execute_handler_async(self, handler, event_data):
        if asyncio.iscoroutinefunction(handler):
            await handler(event_data)
        else:
            handler(event_data)

    async def _execute_observer_async(self, observer, event_type, event_data):
        await observer.notify(event_type, event_data)


class Observer:
    def __init__(self, name):
        self.name = name
        self.observers = []

    def register_observer(self, observer):
        self.observers.append(observer)

    async def notify(self, event_type, event_data):
        for observer in self.observers:
            await observer.handle_event_async(event_type, event_data)
