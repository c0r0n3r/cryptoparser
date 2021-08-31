# -*- coding: utf-8 -*-

import enum
import attr

import six


@attr.s
class InvalidDataLength(Exception):
    bytes_needed = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))


@attr.s
class NotEnoughData(InvalidDataLength):
    def __str__(self):
        return 'not enough data received from target; missing_byte_count="{}"'.format(self.bytes_needed)


@attr.s
class TooMuchData(InvalidDataLength):
    def __str__(self):
        return 'too much data received from target; rest_byte_count="{}"'.format(self.bytes_needed)


@attr.s(init=False)
class InvalidValue(Exception):
    value = attr.ib()

    def __init__(self, value, type_class, class_member=None):
        if isinstance(value, enum.IntEnum):
            message = hex(value.value)
        elif isinstance(value, int):
            message = hex(value)
        else:
            message = value
        message = hex(value) if isinstance(value, int) else repr(value)
        type_name = type_class.__name__ if hasattr(type_class, '__name__') else str(type(type_class))
        message = six.ensure_text('{} is not a valid {}').format(message, type_name)
        if class_member is not None:
            message = six.ensure_text('{} {} value').format(message, class_member)

        super(InvalidValue, self).__init__(message)

        self.value = value


class InvalidType(Exception):
    def __str__(self):
        return 'invalid type value received from target'
