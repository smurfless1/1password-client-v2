from onepassword import OnePassword


print("This walks through an initial connection to 1Password CLI v2, so you know the client is ready.")
op = OnePassword()
vaults = op.list_vaults()
assert(bool(vaults))
print("All set!")
