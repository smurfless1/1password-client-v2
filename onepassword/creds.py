import platform
from dataclasses import dataclass
from functools import cached_property
from typing import Optional

from onepassword.settings import Settings
from onepassword.string_encryptor import StringEncryptor


@dataclass
class OnePasswordCreds:
    """1password credential and state storage"""

    # shorthand name for your 1password account e.g. wandera from wandera.1password.com (optional, default=None)
    account: Optional[str] = None
    # full domain name of 1password account e.g. wandera.1password.com (optional, default=None)
    domain: Optional[str] = None
    # email address of 1password account (optional, default=None)
    email: Optional[str] = None
    # secret_key: secret key of 1password account (optional, default=None)
    encrypted_secret: Optional[bytes] = None
    # password: password for 1password account (optional, default=None)
    encrypted_password: Optional[bytes] = None

    session_key: Optional[str] = None

    @cached_property
    def encryptor(self):
        return StringEncryptor(str.encode(f"{platform.node():>32}"[:32]))

    @property
    def password(self) -> Optional[str]:
        if self.encrypted_password is not None:
            return self.encryptor.decode(self.encrypted_password)
        return None

    @password.setter
    def password(self, value: str):
        self.encrypted_password = self.encryptor.encode(value)

    @property
    def secret(self) -> Optional[str]:
        if self.encrypted_secret is not None:
            return self.encryptor.decode(self.encrypted_secret)
        return ''

    @secret.setter
    def secret(self, value: str):
        self.encrypted_secret = self.encryptor.encode(value)

    @property
    def session_key_name(self) -> str:
        return f'OP_SESSION_{self.account}'

    def load(self):
        setting_file = Settings()
        with setting_file.open() as settings:
            self.account = settings.get(Settings.ACCOUNT_KEY)
            self.domain = settings.get(Settings.DOMAIN_KEY)
            self.email = settings.get(Settings.EMAIL_KEY)
            self.encrypted_secret = settings.get(Settings.SECRET_KEY)
            self.encrypted_password = settings.get(Settings.MASTER_PW_KEY)
            self.session_key = settings.get(Settings.SESSION_KEY)

    def save(self):
        setting_file = Settings()
        with setting_file.open() as settings:
            settings[Settings.ACCOUNT_KEY] = self.account
            settings[Settings.DOMAIN_KEY] = self.domain
            settings[Settings.EMAIL_KEY] = self.email
            settings[Settings.SECRET_KEY] = self.encrypted_secret
            settings[Settings.MASTER_PW_KEY] = self.encrypted_password
            settings[Settings.SESSION_KEY] = self.session_key
