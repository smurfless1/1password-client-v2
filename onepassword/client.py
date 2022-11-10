import os
import json
from typing import Optional, List, Union, Dict

import yaml
from json import JSONDecodeError

from onepassword.session_manager import SessionManager


class OnePassword(SessionManager):
    """ Class for integrating with a 1Password CLI password manager after it is signed in."""

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

    def list_vaults(self) -> List[str]:
        """Helper function to list all vaults"""
        returned: List[str] = self.read_bash_return('op vault list').splitlines(keepends=False)
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
