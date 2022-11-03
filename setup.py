from pathlib import Path
from setuptools import setup


root_dir = Path(__file__).parent


def readme():
    with (root_dir / 'README.md').open('r', encoding='utf-8') as f:
        return f.read()


with (root_dir / 'VERSION').open('r', encoding='utf-8') as version_handle:
    version = version_handle.read().strip()


setup(
    name="1password",
    version=version,
    author="David Pryce",
    author_email="david.pryce@wandera.com",
    description="A Python client and wrapper around the 1Password CLI.",
    long_description=readme(),
    long_description_content_type='text/markdown',
    install_requires=[
        "wget",
        "pyyaml",
        "pycryptodome",
        "pexpect"
    ],
    python_requires='>=3.7',
    license="MIT",
    url="https://github.com/wandera/1password-client",
    classifiers=["Programming Language :: Python :: 3 :: Only",
                 "License :: OSI Approved :: MIT License",
                 "Operating System :: MacOS :: MacOS X",
                 "Operating System :: POSIX",
                 "Operating System :: Unix"],
    packages=["onepassword"],
    tests_require=["pytest"],
    setup_requires=["wget"]
)
