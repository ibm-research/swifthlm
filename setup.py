# -*- encoding: utf-8 -*-
name = 'swifthlm'
entry_point = '%s.middleware:filter_factory' % (name)
version = '0.2.1'

from setuptools import setup, find_packages

setup(
    name=name,
    version=version,
    packages=find_packages(),
    install_requires=['swift'],
    entry_points={
        'paste.filter_factory': ['%s=%s' % (name, entry_point)]
    },
)
