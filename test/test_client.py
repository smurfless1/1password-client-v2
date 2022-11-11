import unittest

from onepassword import OnePassword, OnePasswordCreds
from onepassword.client import FieldType
from onepassword.settings import Settings


class FunctionalTest(unittest.TestCase):
    def test_reads_vaults(self):
        op = OnePassword()
        vaults = op.list_vaults()
        self.assertTrue(bool(vaults))
        self.assertTrue('Personal' in vaults)

    def test_lists_items(self):
        op = OnePassword()
        response = op.list_items("Shared")
        self.assertTrue(isinstance(response, list))
        self.assertTrue(isinstance(response[0], dict))

    def test_reads_fields(self):
        op = OnePassword()
        field_name = 'password'
        field_names = ['username', 'password']
        response = op.get_item_fields('no such item', field_name)
        self.assertFalse(bool(response))
        response = op.get_item_fields('Test Password', field_name)
        self.assertTrue(bool(response))
        self.assertEqual('what a terrible password', response[field_name])
        response = op.get_item_fields('Test Password', field_names)
        self.assertTrue(bool(response))
        self.assertEqual('fake.for.testing@smurfless.com', response['username'])
        self.assertEqual('what a terrible password', response['password'])

    def test_creates_and_edits_items(self):
        """For keyring compliance, we can create, update, and get passwords."""
        op = OnePassword()
        item_name = 'Ignore'
        username = 'foo'
        password = 'bar'
        vault_name = 'Personal'
        op.create_login(username=username, password=password, title=item_name, vault=vault_name)
        response = op.get_item_fields(item_name, 'username')
        self.assertTrue(response['username'] in ['foo', 'biz'])
        op.edit_item_username(uuid=item_name, value='biz')
        response = op.get_item_fields(item_name, 'username')
        self.assertEqual('biz', response['username'])
        op.delete_item(item_name, vault=vault_name)
        response = op.get_item_fields(item_name, 'username')
        self.assertFalse(response)

    def test_settings(self):
        bp = Settings()
        key = 'OP_SESSION_smurfless'
        expected = '0BiDmjLgT2oCMXgHaaMXMJTxA2ZYOJWEMpyQm6bIi4I'
        bp.update_profile(key, expected)
        out = bp.get_key_value(key)
        with bp.open() as settings:
            self.assertTrue(key in settings)
        self.assertEqual(out[0][key], expected)

    def test_creds_to_file(self):
        expected = 'this is a big password'
        creds = OnePasswordCreds()
        self.assertEqual(None, creds.password)
        creds.password = expected
        creds.secret = expected
        creds.save()
        self.assertEqual(expected, creds.password)
        self.assertNotEqual(expected, creds.encrypted_password)
        self.assertEqual(expected, creds.secret)
        self.assertNotEqual(expected, creds.encrypted_secret)

        creds2 = OnePasswordCreds()
        creds2.load()
        self.assertEqual(expected, creds2.password)
        self.assertEqual(expected, creds2.secret)


if __name__ == '__main__':
    unittest.main()
