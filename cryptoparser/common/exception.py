#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum


class InvalidDataLength(Exception):
    def __init__(self, bytes_needed=None):
        super(InvalidDataLength, self).__init__()

        self.bytes_needed = bytes_needed


class NotEnoughData(InvalidDataLength):
    pass


class TooMuchData(InvalidDataLength):
    pass


class InvalidValue(Exception):
    def __init__(self, value, type_class, class_member=None):
        message = hex(value) if isinstance(value, int) else '{}'.format(value)
        message = '{} is not a valid {}'.format(message, type_class.__name__)
        if class_member is not None:
            message = '{} {} value'.format(message, class_member)

        super(InvalidValue, self).__init__(message)

        self.value = value


class InvalidType(Exception):
    pass


class NetworkErrorType(enum.IntEnum):
    NO_CONNECTION = 0
    NO_RESPONSE = 1


class NetworkError(IOError):
    def __init__(self, error):
        super(NetworkError, self).__init__()

        self.error = error
