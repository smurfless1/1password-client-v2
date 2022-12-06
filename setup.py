# -*- coding: utf-8 -*-
from setuptools import setup

packages = \
['onepassword']

package_data = \
{'': ['*']}

install_requires = \
['pexpect>=4.8.0,<5.0.0',
 'pycryptodome>=3.16.0,<4.0.0',
 'pyyaml>=6.0,<7.0',
 'wget>=3.2,<4.0']

setup_kwargs = {
    'name': 'onepassword',
    'version': '2.0.2',
    'description': 'CLI wrapper for 1Password v2',
    'long_description': 'None',
    'author': 'David Brown',
    'author_email': 'forums@smurfless.com',
    'maintainer': 'None',
    'maintainer_email': 'None',
    'url': 'None',
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'python_requires': '>=3.7,<4.0',
}


setup(**setup_kwargs)

