from getpass import getpass
from typing import List
from pathlib import Path

import pexpect
from pexpect import TIMEOUT

from onepassword.creds import OnePasswordCreds
from onepassword.decorators import retry
from onepassword.utils import domain_from_email, read_bash_return


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
        self.creds.session_key = self._spawn_signin(op_command, str.encode(self.creds.password))
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

    def add_account_to_cli(self):
        """op account add

Enter your sign-in address (example.1password.com):
Enter the email address for your account on smurfless.1password.com:
Enter the Secret Key for business@smurfless.com on smurfless.1password.com:
Enter the password for business@smurfless.com at smurfless.1password.com:
Now run 'eval $(op signin)' to sign in.
        """
        self.fill_creds()
        child = pexpect.spawn('op account add')
        child.expect('Enter your sign-in address .*: ')
        child.sendline(self.creds.domain)
        child.expect(f'Enter the email address for your account on {self.creds.domain}: ')
        child.sendline(self.creds.email)
        child.expect(f'Enter the Secret Key for {self.creds.email} on {self.creds.domain}: ')
        child.sendline(self.creds.secret)
        child.expect(f'Enter the password for {self.creds.email} at {self.creds.domain}: ')
        child.sendline(self.creds.password)
        child.expect("Now run '.*' to sign in.")

    def _spawn_signin(self, command, m_password: bytes) -> str:
        if command == "":
            raise IOError("Spawn command not valid")
        child = pexpect.spawn(command)
        resp = child.expect([no_accounts_configured, pexpect.EOF, TIMEOUT], timeout=4.0)
        if resp == 0:
            child.close()
            self.add_account_to_cli()
            child = pexpect.spawn(command)

        resp = child.expect([master_password_regex, pexpect.EOF])
        if resp != 1:
            if child.isalive():
                try:
                    child.sendline(m_password)
                except OSError:
                    child.close()
                    child = pexpect.spawn(command)
                    child.expect([master_password_regex, pexpect.EOF])
                    child.sendline(m_password)
            else:
                child.close()
                child = pexpect.spawn(command)
                resp = child.expect([master_password_regex, pexpect.EOF])
                if resp == 0:
                    child.sendline(m_password)
        resp = child.expect(['Enter your six-digit authentication code:', pexpect.EOF])
        if resp != 1:
            auth_code = str(input("Please input your 1Password six-digit authentication code: "))
            child.sendline(auth_code)
            child.expect(pexpect.EOF)
        before = child.before
        child.close()
        if before:
            try:
                sess_key = get_session_key(child.before)
                return sess_key
            except (ValueError,IndexError):
                settingsfile = Path('~/.onepassword.pkl.db').expanduser()
                if settingsfile.exists():
                    settingsfile.unlink()
        return ''


master_password_regex = "Enter the password for .* at .*"
no_accounts_configured = "Do you want to add an account manually"


def get_session_key(process_resp_before: bytes) -> str:
    new_line_response = [x for x in str(process_resp_before).split(" ") if "\\r\\n" in x]
    if len(new_line_response) != 1:
        raise IndexError("Session keys not parsed correctly from response: {}.".format(process_resp_before))
    else:
        return new_line_response[0].split("\\r\\n")[1][:-1]
