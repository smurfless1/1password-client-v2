import os
import json
from time import sleep
from typing import Optional, List, Union, Dict
from functools import partialmethod

import pexpect
import yaml
from json import JSONDecodeError

from onepassword.session_manager import SessionManager


class FieldType:
    PASSWORD = 'password'
    TEXT = 'text'


class DefaultFields:
    PASSWORD = 'password'
    USERNAME = 'username'


def vault_arg(vault):
    vault_arg = f"--vault='{vault}'" if vault else ''
    return vault_arg


class OnePassword(SessionManager):
    """ Class for integrating with a 1Password CLI password manager after it is signed in."""

    def get_uuid(self, docname: str, vault: Optional[str] = None) -> str:  # pragma: no cover
        """
        Helper function to get the uuid for an item

        :param docname: title of the item (not filename of documents)
        :param vault: vault the item is in (optional)
        :returns: uuid of item or None if doesn't exist

        """
        items = self.list_items(vault=vault)
        for t in items:
            if t['overview']['title'] == docname:
                return t['uuid']

    def get_uuids(self, title: str, vault: Optional[str] = None) -> Dict[str, str]:  # pragma: no cover
        """
        Get a map of uuid: additional_information for each match on a title

        :returns: uuid of item or None if doesn't exist
        """
        items = self.list_items(vault=vault)
        filtered = {
            t.get('id'): t.get('additional_information')
            for t in items
            if t.get('title') == title
        }

        return filtered

    def get_first_uuid_with_hint(self, title, hint: str, vault: Optional[str] = None) -> Optional[str]:
        matches: Dict = self.get_uuids(title, vault)
        for uuid, additional in matches.items():
            if hint in additional:
                return uuid
        return None

    def get_document(self, docname: str, vault: Optional[str] = None) -> Optional[dict]:  # pragma: no cover
        """
        Helper function to get a document

        :param docname: title of the document (not it's filename)
        :param vault: vault the document is in (optional)
        :returns: document or None if doesn't exist
        """
        docid = self.get_uuid(docname, vault=vault)
        local_vault_arg = vault_arg(vault)
        try:
            return json.loads(self.read_bash_return(f"op document get {docid} {local_vault_arg}"))
        except JSONDecodeError:
            yaml_attempt = yaml.safe_load(self.read_bash_return(f"op document get {docid} {local_vault_arg}"))
            if isinstance(yaml_attempt, dict):
                return yaml_attempt
            else:
                print(f"File {docname} does not exist")
                return None

    def put_document(self, filename: str, title: str, vault: Optional[str] = None):  # pragma: no cover
        """
        Helper function to put a document

        :param filename: path and filename of document (must be saved locally already)
        :param title: title you wish to call the document
        :param vault: vault the document is in (optional)
        """
        cmd = f"op document create {filename} --title={title} {vault_arg(vault)}"
        # [--tags=<tags>]
        response = self.read_bash_return(cmd)
        if len(response) == 0:
            self._signin()
            self.read_bash_return(cmd)

    def delete_item(self, uuid: str, vault: Optional[str] = None):  # pragma: no cover
        """
        Helper function to delete an item

        :param uuid: uuid of the item you wish to remove
        :param vault: vault the document is in (optional)
        """
        cmd = f"op item delete \"{uuid}\" {vault_arg(vault)}"
        response = self.read_bash_return(cmd)
        if len(response) > 0:
            self._signin()
            self.read_bash_return(cmd)

    def delete_document(self, title: str, vault: Optional[str] = None):  # pragma: no cover
        """
        Helper function to delete a document

        :param title: title of the document you wish to remove
        :param vault: vault the document is in (optional)
        """
        docid = self.get_uuid(title, vault=vault)
        cmd = f"op item delete {docid} {vault_arg(vault)}"
        response = self.read_bash_return(cmd)
        if len(response) > 0:
            self._signin()
            self.read_bash_return(cmd)

    def update_document(self, filename: str, title: str, vault: Optional[str] = None):  # pragma: no cover
        """
        Helper function to update an existing document in 1Password.

        :param title: name of the document in 1Password.
        :param filename: path and filename of document (must be saved locally already).
        :param vault: vault the document is in (optional).
        """
        # delete the old document
        self.delete_document(title, vault=vault)

        # put the new updated one
        self.put_document(filename, title, vault=vault)

        # remove the saved file locally
        os.remove(filename)

    def list_items(self, vault: Optional[str] = None) -> dict:
        """
        Helper function to list all items in a certain vault

        :param vault: vault the items are in (optional)

        :returns: dict of all items
        """
        self.sign_in_if_needed()
        items = json.loads(self.read_bash_return(
            f"op item list --format=json {vault_arg(vault)}"))
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
        self.sign_in_if_needed()
        if isinstance(fields, list):
            returned = self.read_bash_return(
                f"op item get \"{uuid}\" --format=json --fields {','.join(fields)}"
            )
            if "isn't an item" in returned:
                return {}
            items: List[Dict] = json.loads(returned)
            item = {elt.get('id'): elt.get('value') for elt in items}
        elif isinstance(fields, str):
            returned = self.read_bash_return(f"op item get \"{uuid}\" --fields {fields}").strip()
            if "isn't an item" in returned:
                return {}
            item = {fields: returned}
        else:
            returned = self.read_bash_return(f"op item get \"{uuid}\" --format=json")
            if "isn't an item" in returned:
                return {}
            item = json.loads(returned)
        return item

    def edit_item_field(
        self,
        fieldtype: str,
        uuid: str,
        field: str,
        value: str,
    ):
        """op item edit 'Test Password' username='fake.for.testing@smurfless.com'"""
        self.sign_in_if_needed()
        # more types?
        formatted = field if field in [DefaultFields.USERNAME, DefaultFields.PASSWORD] else f"{field}[{fieldtype}]"
        cmd = f"op item edit \"{uuid}\" \"{formatted}={value}\""
        self.read_bash_return(cmd)

    edit_item_username = partialmethod(edit_item_field, fieldtype=FieldType.TEXT, field=DefaultFields.USERNAME)
    edit_item_password = partialmethod(edit_item_field, fieldtype=FieldType.PASSWORD, field=DefaultFields.PASSWORD)

    def create_login(
        self,
        username: str,
        password: str,
        title: str,
        vault: Optional[str] = None
    ):  # pragma: no cover
        """
        Helper function to put a document
        :param username: username to be stored
        :param password: password to be stored
        :param title: title you wish to call the login
        :param vault: vault the document is in (optional)
        """
        self.sign_in_if_needed()
        op_command = f'op item create --category=login "username={username}" "password={password}" --title="{title}" ' \
                     f'{vault_arg(vault)}'
        try:
            # there is a rather serious bug in 1password CLI v2 that locks up with the normal subprocess calls
            # yes they are aware, no their fix didn't work.
            response = self.read_bash_return(op_command)
            if 'ERROR' in response or len(response) == 0:
                raise ValueError("1Password reported an error creating an item from the CLI.")
            return
        except:
            # however, THIS works fine. Just not on Windows.
            command = f'bash -c \'{self.creds.session_key_name}={self.creds.session_key} {op_command}\''
            my_env = os.environ.copy()
            my_env[self.creds.session_key_name] = self.creds.session_key
            child = pexpect.spawn(command, env=my_env)
            sleep(7)
            child.close()
            # stupidly it also takes a second or two to settle
            sleep(2)

    def create_device(self, filename: str, category: str, vault: Optional[str] = None):  # pragma: no cover
        """untested, from a fork: merkelste"""
        self.sign_in_if_needed()
        cmd = f'op item create --category device "{category}" "$(op encode < {filename})" {vault_arg(vault)}'
        response = self.read_bash_return(cmd)
        if len(response) == 0:
            self._signin()
            self.read_bash_return(cmd)
