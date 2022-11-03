# OnePassword python client
[![PyPi release](https://github.com/smurfless1/1password-client/actions/workflows/publish-to-pypi.yml/badge.svg?branch=main&event=push)](https://github.com/wandera/1password-client/actions/workflows/publish-to-pypi.yml)
[![CodeQL](https://github.com/smurfless1/1password-client/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/wandera/1password-client/actions/workflows/codeql-analysis.yml)

Python client around the 1Password password manager cli for usage within python code and
Jupyter Notebooks. Originally developed by Data Scientists from Wandera (a Jamf company).

This fork is rewritten over the 1password CLI version 2.

To test initial setup (including caching an encrypted copy of your master password so later scripts do not stop to ask)
run the following:

`python -m onepassword`

Returning users

There were some big changes. This library no longer tries to install the binary 1password CLI for you.
This limits the responsibility of this package, whose main purpose is to translate between 1password CLI and python.
The amount of fiddling around with security settings in the OS and 1password itself just made it unsuited to this 
kind of integration. Use homebrew or puppet or something else if managing at scale.

The wrapper around CLI v1.x tried to maintain the shell environment, so you could also hop in and out of new shells.

That's over now.

My reasoning is this: Under no circumstances do I expect a password client to edit my .zshrc. I feel this is too risky.
Instead, this will maintain a separate session variable, which probably invalidates the one from your current shell 
sessions. This seems like the right thing to do. 

If you don't like it, feel free to fork and go back to the old risky method.

## Installation
```bash
pip install 1password
```

If you have issues with PyYaml or other distutils installed packages then use:
```bash
pip install --ignore-installed 1password
```

You must manage `op` yourself by visiting 
https://support.1password.com/command-line-getting-started/

### Optional pre-requisites
#### base32
This utility is used to create a unique guid for your device but this isn't a hard requirement from AgileBits 
and so if you see `base32: command not found` an empty string will be used instead, 
and the client will still work fully.

If you really want to, you can make sure you have this installed by installing coreutils. Details per platform can
be found here: https://command-not-found.com/base32

## Basic Usage
Currently tested on macOS and Linux.

On first usage users will be asked for both the enrolled email, secret key and password. 
There is also verification of your account domain and name. 

For all following usages you will only be asked for a password.

You will be given 3 attempts and then pointed to reset password documentation, or alternatively you can
restart your kernel.

No passwords are stored in memory without encryption.

If you have 2FA turned on for your 1Password account the client will ask for your six digit authenticator code.

```python
from onepassword import OnePassword
from typing import Dict, List

op = OnePassword()

# List all vaults 
vaults: List[str] = op.list_vaults()

# List all items in a vault, default is Private
all_items_in_vault: Dict = op.list_items()

# Get all fields, one field or more fields for an item with uuid="example"
op.get_item_fields(uuid="example")
op.get_item_fields(uuid="example", fields="username")
op.get_item_fields(uuid="example", fields=["username", "password"])

```

### Input formats
To be sure what you are using is of the right format

- Enrolled email: standard email format e.g. user@example.com 
- Secret key: provided by 1Password e.g. ##-######-######-#####-#####-#####-#####
- Account domain: domain that you would login to 1Password via browser e.g. example.1password.com
- Account name: subdomain or account name that cli can use for multiple account holders e.g. example

## Contributing 
The GitHub action will run a full build, test and release on any push. 
If this is to the main branch then this will release to public PyPi and bump the patch version.

For a major or minor branch update your new branch should include this new version and this should be verified by the 
code owners.

In general, this means when contributing you should create a feature branch off of the main branch and without 
manually bumping the version you can focus on development.

## CLI coverage
Full op documentation can be found here: https://support.1password.com/command-line-reference/

The below is correct as of version 0.3.0.
### Commands
This is the set of commands the current python SDK covers:
- create: Create an object
    - document
- delete: Remove an object
    - item: we use this method to remove documents but now there is a new delete document method
- get: Get details about an object
    - document
    - item
- list: List objects and events
    - items
    - vaults
- signin: Sign in to a 1Password account
- signout: Sign out of a 1Password account


This is what still needs developing due to new functionality being released:
- add: Grant access to groups or vaults
    - group 
    - user
- completion: Generate shell completion information
- confirm: Confirm a user
- create: Create an object
    - group
    - user
    - item
    - vault 
- delete: Remove an object
    - document
    - user
    - vault
    - group
    - trash
- edit: Edit an object
    - document
    - group
    - item
    - user
    - vault
- encode: Encode the JSON needed to create an item
- forget: Remove a 1Password account from this device
- get: Get details about an object
    - account
    - group
    - template
    - totp
    - user
    - vault
- list: List objects and events
    - documents
    - events
    - groups
    - templates
    - users
- reactivate: Reactivate a suspended user
- remove: Revoke access to groups or vaults
- suspend: Suspend a user
- update: Check for and download updates

## Roadmap
- Add Windows functionality
- Add clean uninstall of client and op
- Remove subprocess usage everywhere -> use pexpect
- Add test docker image
- Get full UT coverage
- Align response types into JSON / lists instead of JSON strings
- Ensure full and matching functionality of CLI in python
    - add
    - confirm
    - create
    - delete
    - edit
    - encode
    - forget
    - get
    - list
    - reactivate
    - remove
    - suspend
- Use the new CLI update method
