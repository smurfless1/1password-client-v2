import os
import json
import platform
from dataclasses import dataclass
from typing import Optional, List, Union, Any, Tuple, Dict

import yaml
from getpass import getpass
from json import JSONDecodeError

from onepassword.exceptions import OnePasswordForgottenPassword
from onepassword.utils import read_bash_return, domain_from_email, get_device_uuid, _spawn_signin
from onepassword.settings import Settings
from onepassword.encrypted_string import EncryptedString



@dataclass
class OnePasswordCreds:

    # shorthand name for your 1password account e.g. wandera from wandera.1password.com (optional, default=None)
    account: Optional[str] = None
    # full domain name of 1password account e.g. wandera.1password.com (optional, default=None)
    domain: Optional[str] = None
    # email address of 1password account (optional, default=None)
    email: Optional[str] = None
    # secret_key: secret key of 1password account (optional, default=None)
    secret: Optional[str] = None
    # todo only store encrypted bytes instead?
    # master_password: password for 1password account (optional, default=None)
    password: Optional[str] = None
    encrypted_password: Optional[bytes] = None


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
        self.signin_domain = creds.domain
        self.email_address = creds.email
        self.secret_key: str = creds.secret
        self.encrypted_master_password: bytes = ''.encode('utf-8')
        bp = Settings()
        os.environ["OP_DEVICE"] = get_device_uuid(bp)
        # reuse existing op session
        with bp.open() as settings:
            if Settings.ACCOUNT_KEY in settings:
                creds.account = settings.get(Settings.ACCOUNT_KEY)
        if isinstance(creds.account, str) and "OP_SESSION_{}".format(creds.account) in settings:
            # reuse all existing values
            pass
        elif self.session_var_in_environment(bp):
            # just the password (if not cached)
            self.encrypted_master_password, self.session_key = self.signin_wrapper(creds)
        else:
            # full first time setup
            self.first_use(creds=creds)

    @staticmethod
    def session_var_in_environment(bp):
        cache = Settings()
        found = False
        with cache.open() as settings:
            for key in settings.keys():
                if Settings.SESSION_KEY in key:
                    found = True
        return found

    def first_use(
        self,
        creds: Optional[OnePasswordCreds] = OnePasswordCreds()
    ):  # pragma: no cover
        """
        Helper function to perform first time signin either with user interaction or not, depending on _init_
        """
        creds.email = creds.email or input("Please input your email address used for 1Password account: ")
        creds.account = creds.account or domain_from_email(creds.email)
        creds.domain = creds.domain or creds.account + ".1password.com"
        creds.secret = creds.secret or getpass("Please input your 1Password secret key: ")
        self.signin_wrapper(creds)

    def signin_wrapper(
        self,
        creds: OnePasswordCreds,
    ) -> Tuple[bytes, str]:
        # pragma: no cover
        """
        Helper function for user to sign in but allows for three incorrect passwords. If successful signs in and updates
        bash profile, if not raises exception and points user to 1Password support.

        :param creds: credentials
        :return: encrypted_str, session_key - used by signin to know of existing login
        """

        password, session_key, domain, account, bp = \
            self._signin(creds)
        tries = 1
        while tries < 3:
            if "(ERROR)  401" in session_key:
                print("That's not the right password, try again.")
                password, session_key, domain, account, bp = self._signin(creds)
                tries += 1
                pass
            else:
                # device_uuid = generate_uuid()
                session_final_key = f"OP_SESSION_{creds.account}"
                session_final_value = session_key.replace("\n", "")
                os.environ[session_final_key] = session_final_value
                bp.update_profile(session_final_key, session_final_value)
                key_value = session_key if bool(session_key) else str.encode(f"{platform.node():>32}"[:32])
                encrypt = EncryptedString(key_value)
                encrypted_pass_bytes = encrypt.encode(password.decode() if isinstance(password, bytes) else password)
                return encrypted_pass_bytes, session_key
        raise OnePasswordForgottenPassword("You appear to have forgotten your password, visit: "
                                           "https://support.1password.com/forgot-master-password/")

    @staticmethod
    def _signin(
        creds: OnePasswordCreds,
    ) -> tuple[Optional[bytes], Any, Optional[str], Optional[Union[str, Any]], Settings]:  # pragma: no cover
        """
        Re-sign-in to the CLI as required

        :param account: shorthand name for your 1password account e.g. wandera from wandera.1password.com (optional,
        default=None)
        :param domain: full domain name of 1password account e.g. wandera.1password.com (optional, default=None)
        :param email: email address of 1password account (optional, default=None)
        :param secret_key: secret key of 1password account (optional, default=None)
        :param master_password: password for 1password account (optional, default=None)
        :return: master_password, sess_key, domain, bp - all used by wrapper
        """
        bp = Settings()
        op_command = ""
        if creds.password is not None:
            master_password_bytes = str.encode(creds.password)
        else:
            if 'op' in locals():
                initiated_class = locals()["op"]
                if 'session_key' and 'encrypted_master_password' in initiated_class.__dict__:
                    encrypt = EncryptedString(initiated_class.session_key)
                    master_password_bytes = str.encode(encrypt.decode(initiated_class.encrypted_master_password))
            else:
                with bp.open() as cache:
                    encryptor = EncryptedString(str(Settings.MASTER_PW_CACHE))
                    if Settings.MASTER_PW_KEY in cache:
                        encrypted_password = cache[Settings.MASTER_PW_KEY]
                        master_password = encryptor.decode(encrypted_password)
                        master_password_bytes = str.encode(master_password)
                    else:
                        master_password = getpass("Please input your 1Password master password: ")
                        encrypted_pass_bytes = encryptor.encode(master_password)
                        cache[Settings.MASTER_PW_KEY] = encrypted_pass_bytes
                        master_password_bytes = str.encode(master_password)
        if creds.secret:
            op_command = f"op signin --account {creds.account} --raw"
        else:
            if creds.account is None:
                try:
                    session_dict = bp.get_key_value("OP_SESSION", fuzzy=True)[0]  # list of dicts from BashProfile2
                    creds.account = list(session_dict.keys())[0].split('OP_SESSION_')[1]
                except AttributeError:
                    creds.account = input("Please input your 1Password account name e.g. wandera from "
                                    "wandera.1password.com: ")
                except ValueError:
                    raise ValueError("First signin failed or not executed.")
            op_command = "op signin --raw"

        if creds.account is not None:
            with bp.open() as cache:
                cache[Settings.ACCOUNT_KEY] = creds.account
        sess_key = _spawn_signin(op_command, master_password_bytes)
        return master_password_bytes, sess_key, creds.domain, creds.account, bp

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
            return json.loads(read_bash_return("op document get {} --vault='{}'".format(docid, vault), single=False))
        except JSONDecodeError:
            yaml_attempt = yaml.safe_load(read_bash_return("op document get {} --vault='{}'".format(docid, vault),
                                                           single=False))
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
        response = read_bash_return(cmd)
        if len(response) == 0:
            self._signin()
            read_bash_return(cmd)

    def delete_document(self, title: str, vault: str = "Private"):  # pragma: no cover
        """
        Helper function to delete a document

        :param title: title of the document you wish to remove
        :param vault: vault the document is in (optional, default=Private)
        """
        docid = self.get_uuid(title, vault=vault)
        cmd = "op item delete {} --vault='{}'".format(docid, vault)
        response = read_bash_return(cmd)
        if len(response) > 0:
            self._signin()
            read_bash_return(cmd)

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

    @staticmethod
    def list_vaults() -> List[str]:
        """Helper function to list all vaults"""
        returned: List[str] = read_bash_return('op vault list', single=False).splitlines(keepends=False)
        names = [line.split(maxsplit=1)[-1] for line in returned[1:]]
        return names

    @staticmethod
    def list_items(vault: str = "Private") -> dict:
        """
        Helper function to list all items in a certain vault

        :param vault: vault the items are in (optional, default=Private)

        :returns: dict of all items
        """
        items = json.loads(read_bash_return(f"op item list --format=json --vault='{vault}'", single=False))
        return items

    @staticmethod
    def get_item_fields(
            uuid: Union[str, bytes],
            fields: Optional[Union[str, bytes, Optional[List[Union[str, bytes]]]]] = None) -> dict:
        """
        Helper function to get a certain field, you can find the UUID you need using list_items

        :param uuid: uuid of the item you wish to get, no vault needed
        :param fields: to return only certain detail use either a specific field or list of them
        (optional, default=None which means all fields returned)
        :return: item :obj: `dict`: dict of the item with requested fields
        """
        if isinstance(fields, list):
            returned = read_bash_return(f"op item get \"{uuid}\" --format=json --fields {','.join(fields)}", single=False)
            items: List[Dict] = json.loads(returned)
            item = {elt.get('id'): elt.get('value') for elt in items}
        elif isinstance(fields, str):
            item = {fields: read_bash_return(f"op item get \"{uuid}\" --fields {fields}")}
        else:
            item = json.loads(read_bash_return(f"op item get \"{uuid}\" --format=json", single=False))
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
        cmd = f"op item create --category login username={username} password={password} --title={title} --vault={vault}"
        # [--tags=<tags>]
        response = read_bash_return(cmd)
        if len(response) == 0:
            self._signin()
            read_bash_return(cmd)

    def create_device(self, filename: str, category: str, vault: str = "Private"):  # pragma: no cover
        """untested, from a fork: merkelste"""
        cmd = f'op item create --category device "{category}" "$(op encode < {filename})" --vault={vault}'
        response = read_bash_return(cmd)
        if len(response) == 0:
            self._signin()
            read_bash_return(cmd)
