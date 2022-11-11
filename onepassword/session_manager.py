from getpass import getpass
from typing import List

from onepassword.creds import OnePasswordCreds
from onepassword.decorators import retry
from onepassword.utils import _spawn_signin, domain_from_email, read_bash_return


class NotSignedInException(Exception):
    """raise this if you are not signed in"""


class SessionManager:
    """Manage 1password CLI session variables and credentials."""

    def __init__(self):
        self.creds: OnePasswordCreds = OnePasswordCreds()
        self.creds.load()
        self.sign_in_if_needed()

    def fill_creds(
        self,
    ):  # pragma: no cover
        """
        Collect and cache missing user information for signing in to op
        """
        self.creds.email = self.creds.email or input("Please input your email address used for 1Password account: ")
        self.creds.account = self.creds.account or domain_from_email(self.creds.email)
        self.creds.domain = self.creds.domain or self.creds.account + ".1password.com"
        self.creds.secret = self.creds.secret or getpass("Please input your 1Password secret key: ")
        self.creds.password = self.creds.password or getpass("Please input your master password: ")
        self.creds.save()

    def sign_in_if_needed(self):
        if self.creds.session_key is None:
            self.signin_wrapper()
            return

        vaults = self.list_vaults()
        if not bool(vaults):
            self.signin_wrapper()

    @retry((NotSignedInException,), tries=3)
    def signin_wrapper(self):  # pragma: no cover
        """
        Tries to call op signin up to 3 times, allowing the user to update credentials if needed.

        :return: encrypted_str, session_key - used by signin to know of existing login
        """
        if self.creds.encrypted_password is None:
            self.fill_creds()
        self._signin()
        if "are not currently signed in" in self.creds.session_key:
            raise NotSignedInException("Failed to sign in. Trying again.")

    def _signin(self):  # pragma: no cover
        """
        Call op signin with the correct parameters.

        Expects the credentials to already be populated before here.
        Updates the credentials if required.
        """
        op_command = "op signin --raw"
        if self.creds.account is not None:
            op_command = f"op signin --account {self.creds.account} --raw"
        self.creds.session_key = _spawn_signin(op_command, str.encode(self.creds.password))
        self.creds.save()

    def read_bash_return(self, cmd, single=False) -> str:
        """Call op with env vars from the credential set"""
        return read_bash_return(
            cmd,
            self.creds.session_key_name,
            self.creds.session_key,
            single=single,
        )

    def list_vaults(self) -> List[str]:
        """Helper function to list all vaults"""
        returned: List[str] = self.read_bash_return('op vault list').splitlines(keepends=False)
        names = [line.split(maxsplit=1)[-1] for line in returned[1:]]
        return names
