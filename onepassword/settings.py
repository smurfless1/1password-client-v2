import shelve
from contextlib import contextmanager
from pathlib import Path
from typing import List, Dict, Iterable


class Settings:
    MASTER_PW_CACHE = Path("~/.1password-client.pkl").expanduser()
    MASTER_PW_KEY = 'password'  # subtle. I like it.
    SESSION_KEY = 'OP_SESSION'
    DEVICE_KEY = 'OP_DEVICE'
    ACCOUNT_KEY = 'ACCOUNT'

    @contextmanager
    def open(self) -> Iterable[dict]:
        yield shelve.open(str(self.MASTER_PW_CACHE), writeback=True)

    def update_profile(self, key, value):
        with self.open() as settings:
            settings[key] = value

    def get_key_value(self, key, fuzzy: bool = False) -> List[Dict[str, str]]:
        final_key = key
        value = None
        with self.open() as settings:
            if fuzzy:
                for setting_key in settings.keys():
                    if key in setting_key:
                        final_key = setting_key
                        value = settings.get(setting_key)
                        break
            else:
                value = settings.get(key)
        return [{final_key: value}]

    def get(self, key):
        with self.open() as settings:
            value = settings.get(key)

        return value
