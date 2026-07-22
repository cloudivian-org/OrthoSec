from datetime import datetime


def register_tools():
    def get_time():  # read-only, no dangerous capability
        return datetime.now().isoformat()

    return [{"type": "function", "name": "get_time", "fn": get_time}]
