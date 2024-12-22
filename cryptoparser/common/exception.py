# -*- coding: utf-8 -*-

import attr


@attr.s
class InvalidDataLength(Exception):
    bytes_needed = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))


@attr.s
class NotEnoughData(InvalidDataLength):
    def __str__(self):
        return f'not enough data received from target; missing_byte_count="{self.bytes_needed}"'


@attr.s
class TooMuchData(InvalidDataLength):
    def __str__(self):
        return f'too much data received from target; rest_byte_count="{self.bytes_needed}"'


class InvalidType(Exception):
    def __str__(self):
        return 'invalid type value received from target'
