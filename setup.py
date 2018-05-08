#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import unittest

from setuptools import setup


with open(os.path.join(os.getenv('REQUIREMENTS_DIR', ''), 'requirements.txt')) as f:
    install_requirements = f.read().splitlines()


test_requirements = [
    "unittest2",
    "coverage",
]


def test_discover():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests', pattern='test_*.py')
    return test_suite


setup(
    name='cryptoparser',
    version='0.1',
    description='Fast and flexible security protocol parser and generator',
    author='Szilárd Pfeiffer',
    author_email='coroner@pfeifferszilard.hu',
    license='LGPLv3',
    url='https://github.com/c0r0n3r/cryptoparser',

    install_requires=install_requirements,
    extras_require={
        ":python_version < '3'": ["enum34", ],
        ":platform_python_implementation != 'PyPy'": ["cffi >= 1.7"],

        "test": test_requirements,
        "pep8": ["flake8", ],
        "pylint": ["pylint", ],
    },

    packages=[
        'cryptoparser',
        'cryptoparser.common',
        'cryptoparser.ssh',
        'cryptoparser.tls',
    ],

    test_suite='setup.test_discover',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: GNU Lesser General Public License (LGPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Testing'
        'Topic :: Software Development :: Testing :: Traffic Generation'
        'Topic :: System :: Networking',
    ],
)
