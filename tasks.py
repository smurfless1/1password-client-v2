from invoke import task
import keyring

@task
def setup_poetry(c):
    api_key = keyring.get_password('gitea API key', 'smurfless1')
    c.run("poetry source add gitea 'http://sinus.smurfless.com:3000/api/packages/smurfless1/pypi/simple'")
    c.run("poetry config repositories.gitea 'http://sinus.smurfless.com:3000/api/packages/smurfless1/pypi'")
    c.run(f"poetry config pypi-token.gitea {api_key}")

@task
def publish(c):
    c.run(f"poetry publish --build --repository gitea")

@task
def build(c):
    c.run("poetry2setup > setup.py")
    c.run("poetry build")
