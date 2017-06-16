
from setuptools import setup


version = "4.1m2"


install_requires = [
    "cloudify-plugins-common=={version}",
    ]

install_requires = [s.format(version=version) for s in install_requires]


setup(
    packages=['cloudify_fake_load'],
    version=version,
    install_requires=install_requires,
    )
