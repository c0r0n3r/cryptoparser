# -*- coding: utf-8 -*-

import binascii
import inspect


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

    return separator.join([format_str.format(x) for x in bytes(byte_array)])


def bytes_from_hex_string(hex_string, separator=''):
    if separator:
        hex_string = ''.join(hex_string.split(separator))

    try:
        binary_data = binascii.a2b_hex(hex_string)
    except (TypeError, ValueError) as e:
        raise ValueError(*e.args) from e

    return binary_data
