# -*- coding: utf-8 -*-

import enum
import attr


@attr.s
class InvalidDataLength(Exception):
    bytes_needed = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))


@attr.s
class NotEnoughData(InvalidDataLength):
    pass


@attr.s
class TooMuchData(InvalidDataLength):
    pass


@attr.s(init=False)
class InvalidValue(Exception):
    value = attr.ib()

    def __init__(self, value, type_class, class_member=None):
        if isinstance(value, enum.IntEnum):
            message = hex(value.value)
        elif isinstance(value, int):
            message = hex(value)
        else:
            message = '{}'.format(value)
        message = '{} is not a valid {}'.format(message, type_class.__name__)
        if class_member is not None:
            message = '{} {} value'.format(message, class_member)

        super(InvalidValue, self).__init__(message)

        self.value = value


class InvalidType(Exception):
    pass
