# -*- coding: utf-8 -*-

import inspect

import six


def get_leaf_classes(base_class):

    def _get_leaf_classes(base_class):
        subclasses = []

        if base_class.__subclasses__():
            for subclass in base_class.__subclasses__():
                subclasses += _get_leaf_classes(subclass)
        else:
            if not inspect.isabstract(base_class):
                return [base_class, ]

        return subclasses

    return _get_leaf_classes(base_class)


def bytes_to_hex_string(byte_array, separator='', lowercase=False):
    if lowercase:
        format_str = '{:02x}'
    else:
        format_str = '{:02X}'

    return separator.join([format_str.format(x) for x in six.iterbytes(bytes(byte_array))])
