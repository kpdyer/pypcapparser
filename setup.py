import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "pypcapparser",
    version = "0.0.1-beta",
    author = "Kevin P. Dyer",
    author_email = "kpdyer@gmail.com",
    license = "Apache v2",
    packages=['pypcapparser'],
)
