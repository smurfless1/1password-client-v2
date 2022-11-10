from getpass import getpass

from onepassword.creds import OnePasswordCreds
from onepassword.exceptions import OnePasswordForgottenPassword
from onepassword.utils import _spawn_signin, domain_from_email, read_bash_return


class SessionManager:
    """Manage 1password CLI session variables and credentials."""

    def __init__(self):
        self.creds: OnePasswordCreds = OnePasswordCreds()
        self.creds.load()
        if self.creds.session_key is None:
            self.signin_wrapper()

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

    def signin_wrapper(self):  # pragma: no cover
        """
        Tries to call op signin up to 3 times, allowing the user to update credentials if needed.

        :return: encrypted_str, session_key - used by signin to know of existing login
        """
        if self.creds.encrypted_password is None:
            self.creds.load()
            self.fill_creds()
        else:
            self._signin()

        tries = 1
        while tries < 3:
            if "are not currently signed in" in self.creds.session_key:
                print("That's not the right password, try again.")
                self._signin()
                tries += 1
                pass
            return
        raise OnePasswordForgottenPassword("You appear to have forgotten your password, visit: "
                                           "https://support.1password.com/forgot-master-password/")

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
