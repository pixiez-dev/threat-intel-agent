# memory.py

class ConversationMemory:

    def __init__(self):
        self.chat_history = []
        self.last_ioc = None
        self.last_actor = None

    def add_user(self, msg):
        self.chat_history.append(
            {"role": "user", "content": msg}
        )

    def add_assistant(self, msg):
        self.chat_history.append(
            {"role": "assistant", "content": msg}
        )

    def get_history(self):
        return self.chat_history

    def set_last_ioc(self, ioc):
        self.last_ioc = ioc

    def get_last_ioc(self):
        return self.last_ioc
    
    def clear(self):
        """Flushes the active tracking logs to guarantee runtime test isolation."""
        self.chat_history = []
        self.last_ioc = None
        self.last_actor = None