import os
import json
import platform
from dataclasses import dataclass
from functools import cached_property
from typing import Optional, List, Union, Dict

import yaml
from getpass import getpass
from json import JSONDecodeError

from onepassword.exceptions import OnePasswordForgottenPassword
from onepassword.utils import read_bash_return, domain_from_email, get_device_uuid, _spawn_signin
from onepassword.settings import Settings
from onepassword.string_encryptor import StringEncryptor


@dataclass
class OnePasswordCreds:
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

    def save(self):
        setting_file = Settings()
        with setting_file.open() as settings:
            settings[Settings.ACCOUNT_KEY] = self.account
            settings[Settings.DOMAIN_KEY] = self.domain
            settings[Settings.EMAIL_KEY] = self.email
            settings[Settings.SECRET_KEY] = self.encrypted_secret
            settings[Settings.MASTER_PW_KEY] = self.encrypted_password


class OnePassword:
    """ Class for integrating with a 1Password CLI password manager """

    def __init__(
            self,
            creds: Optional[OnePasswordCreds] = OnePasswordCreds()
    ):  # pragma: no cover
        """
        Constructor.

        :param creds: creds
        """
        self.creds: OnePasswordCreds = OnePasswordCreds()
        self.creds.load()

        bp = Settings()
        os.environ["OP_DEVICE"] = get_device_uuid(bp)

        if not isinstance(creds.encrypted_password, bytes):
            self.fill_creds()

        self.signin_wrapper()

    @staticmethod
    def session_var_in_settings():
        cache = Settings()
        found = False
        with cache.open() as settings:
            for key in settings.keys():
                if Settings.SESSION_KEY in key:
                    found = True
        return found

    def fill_creds(
            self,
    ):  # pragma: no cover
        """
        Helper function to perform first time signin either with user interaction or not, depending on _init_
        """
        self.creds.email = self.creds.email or input("Please input your email address used for 1Password account: ")
        self.creds.account = self.creds.account or domain_from_email(self.creds.email)
        self.creds.domain = self.creds.domain or self.creds.account + ".1password.com"
        self.creds.secret = self.creds.secret or getpass("Please input your 1Password secret key: ")
        self.creds.password = self.creds.password or getpass("Please input your master password: ")
        self.creds.save()

    def signin_wrapper(self):
        # pragma: no cover
        """
        Helper function for user to sign in but allows for three incorrect passwords. If successful signs in and updates
        bash profile, if not raises exception and points user to 1Password support.

        :return: encrypted_str, session_key - used by signin to know of existing login
        """

        if self.creds.encrypted_password is None:
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
        """Re-sign-in to the CLI as required"""
        op_command = "op signin --raw"
        if self.creds.account is not None:
            op_command = f"op signin --account {self.creds.account} --raw"
        self.creds.session_key = _spawn_signin(op_command, str.encode(self.creds.password))
        self.creds.save()

    def get_uuid(self, docname: str, vault: str = "Private") -> str:  # pragma: no cover
        """
        Helper function to get the uuid for an item

        :param docname: title of the item (not filename of documents)
        :param vault: vault the item is in (optional, default=Private)
        :returns: uuid of item or None if doesn't exist

        """
        items = self.list_items(vault=vault)
        for t in items:
            if t['overview']['title'] == docname:
                return t['uuid']

    def get_document(self, docname: str, vault: str = "Private") -> Optional[dict]:  # pragma: no cover
        """
        Helper function to get a document

        :param docname: title of the document (not it's filename)
        :param vault: vault the document is in (optional, default=Private)
        :returns: document or None if doesn't exist
        """
        docid = self.get_uuid(docname, vault=vault)
        try:
            return json.loads(self.read_bash_return("op document get {} --vault='{}'".format(docid, vault)))
        except JSONDecodeError:
            yaml_attempt = yaml.safe_load(self.read_bash_return("op document get {} --vault='{}'".format(docid, vault)))
            if isinstance(yaml_attempt, dict):
                return yaml_attempt
            else:
                print("File {} does not exist in 1Password vault: {}".format(docname, vault))
                return None

    def put_document(self, filename: str, title: str, vault: str = "Private"):  # pragma: no cover
        """
        Helper function to put a document

        :param filename: path and filename of document (must be saved locally already)
        :param title: title you wish to call the document
        :param vault: vault the document is in (optional, default=Private)
        """
        cmd = "op document create {} --title={} --vault='{}'".format(filename, title, vault)
        # [--tags=<tags>]
        response = self.read_bash_return(cmd)
        if len(response) == 0:
            self._signin()
            self.read_bash_return(cmd)

    def delete_document(self, title: str, vault: str = "Private"):  # pragma: no cover
        """
        Helper function to delete a document

        :param title: title of the document you wish to remove
        :param vault: vault the document is in (optional, default=Private)
        """
        docid = self.get_uuid(title, vault=vault)
        cmd = "op item delete {} --vault='{}'".format(docid, vault)
        response = self.read_bash_return(cmd)
        if len(response) > 0:
            self._signin()
            self.read_bash_return(cmd)

    def update_document(self, filename: str, title: str, vault: str = 'Private'):  # pragma: no cover
        """
        Helper function to update an existing document in 1Password.

        :param title: name of the document in 1Password.
        :param filename: path and filename of document (must be saved locally already).
        :param vault: vault the document is in (optional, default=Private).
        """
        # delete the old document
        self.delete_document(title, vault=vault)

        # put the new updated one
        self.put_document(filename, title, vault=vault)

        # remove the saved file locally
        os.remove(filename)

    def read_bash_return(self, cmd, single=False) -> str:
        return read_bash_return(
            cmd,
            self.creds.session_key_name,
            self.creds.session_key,
            single=single,
        )

    def list_vaults(self) -> List[str]:
        """Helper function to list all vaults"""
        returned: List[str] = self.read_bash_return(
            'op vault list').splitlines(keepends=False)
        names = [line.split(maxsplit=1)[-1] for line in returned[1:]]
        return names

    def list_items(self, vault: str = "Private") -> dict:
        """
        Helper function to list all items in a certain vault

        :param vault: vault the items are in (optional, default=Private)

        :returns: dict of all items
        """
        self.signin_wrapper()
        items = json.loads(self.read_bash_return(
            f"op item list --format=json --vault='{vault}'"))
        return items

    def get_item_fields(
            self,
            uuid: Union[str, bytes],
            fields: Optional[Union[str, bytes, Optional[List[Union[str, bytes]]]]] = None,
    ) -> dict:
        """
        Helper function to get a certain field, you can find the UUID you need using list_items

        :param uuid: uuid of the item you wish to get, no vault needed
        :param fields: to return only certain detail use either a specific field or list of them
        (optional, default=None which means all fields returned)
        :return: dict of the item with requested fields
        """
        self.signin_wrapper()
        if isinstance(fields, list):
            returned = self.read_bash_return(
                f"op item get \"{uuid}\" --format=json --fields {','.join(fields)}"
            )
            items: List[Dict] = json.loads(returned)
            item = {elt.get('id'): elt.get('value') for elt in items}
        elif isinstance(fields, str):
            item = {fields: self.read_bash_return(f"op item get \"{uuid}\" --fields {fields}").strip()}
        else:
            item = json.loads(self.read_bash_return(f"op item get \"{uuid}\" --format=json"))
        return item

    def create_login(
            self,
            username: str,
            password: str,
            title: str,
            vault: str = "Private"
    ):  # pragma: no cover
        """
        Helper function to put a document
        :param username: username to be stored
        :param password: password to be stored
        :param title: title you wish to call the login
        :param vault: vault the document is in (optional, default=Private)
        """
        self.signin_wrapper()
        cmd = f"op item create --category login username={username} password={password} --title={title} --vault={vault}"
        # [--tags=<tags>]
        response = self.read_bash_return(cmd)
        if len(response) == 0:
            self._signin()
            self.read_bash_return(cmd)

    def create_device(self, filename: str, category: str, vault: str = "Private"):  # pragma: no cover
        """untested, from a fork: merkelste"""
        self.signin_wrapper()
        cmd = f'op item create --category device "{category}" "$(op encode < {filename})" --vault={vault}'
        response = self.read_bash_return(cmd)
        if len(response) == 0:
            self._signin()
            self.read_bash_return(cmd)
