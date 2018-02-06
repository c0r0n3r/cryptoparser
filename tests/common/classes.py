#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptolyzer.common.parse import ParserBinary, ParsableBase, ComposerBinary


class NByteParsable(ParsableBase):
    def __init__(self, value):
        if value < 0 or value >= 2 ** (8 * self.get_byte_size()):
            raise ValueError

        self.value = value

    def __int__(self):
        return self.value

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('value', cls.get_byte_size())

        return cls(parser['value']), cls.get_byte_size()

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.value, self.get_byte_size())

        return composer.composed

    def __repr__(self):
        return '{0:#0{1}x}'.format(self.value, self.get_byte_size() * 2 + 2)

    def __eq__(self, other):
        return self.get_byte_size() == other.get_byte_size() and self.value == other.value

    @classmethod
    def get_byte_size(cls):
        raise NotImplementedError()


class OneByteParsable(NByteParsable):
    @classmethod
    def get_byte_size(cls):
        return 1


class TwoByteParsable(NByteParsable):
    @classmethod
    def get_byte_size(cls):
        return 2
