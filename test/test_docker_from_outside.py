from onepassword import OnePassword
import pexpect

PROMPT = 'root.*'

client = OnePassword()
fields = client.get_item_fields("1Password Account")
subfields = {f.get('id') or f.get('label'): f.get('value') for f in fields.get('fields')}
email = subfields.get('username')
password = subfields.get('password')
secret_key = subfields.get('account-key')

cmd = 'docker run -it op'
child = pexpect.spawn(cmd)
child.expect('.*: ')
child.sendline(email)
child.expect('.*: ')
child.sendline(secret_key)
child.expect('.*: ')
child.sendline(password)
child.expect('All set!')
# print(child.before.decode('utf-8'))
child.close()
