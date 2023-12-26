#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=invalid-name

import datetime

__author__ = 'Szilárd Pfeiffer'
__title__ = 'CryptoParser'


extensions = []
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = __title__
copyright = f'{datetime.datetime.now().year}, {__author__}'  # pylint: disable=redefined-builtin

exclude_patterns = ['_build']

html_theme = 'alabaster'
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
        'relations.html',
        'searchbox.html',
        'donate.html',
    ]
}
html_theme_options = {
    'description': 'Cryptographic protocol and security-related protocol piece parser',
    'fixed_sidebar': True,
    'collapse_navigation': False,
}
