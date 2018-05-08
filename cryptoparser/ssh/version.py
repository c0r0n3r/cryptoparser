#!/usr/bin/env python
# -*- coding: utf-8 -*-

import enum

from cryptoparser.common.exception import InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserText, ComposerText


class SshVersion(enum.IntEnum):
    SSH1 = 1
    SSH2 = 2


class SshProtocolVersion(ParsableBase):
    def __init__(self, major=SshVersion.SSH2, minor=0):
        self._major = SshVersion(major)
        self._minor = int(minor)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        try:
            parser.parse_numeric('major')
            parser.parse_separator('.')
            parser.parse_numeric('minor')
        except ValueError:
            raise InvalidValue(parsable, SshProtocolVersion)

        return SshProtocolVersion(parser['major'], parser['minor']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_numeric(self.major.value)
        composer.compose_separator('.')
        composer.compose_numeric(self.minor)

        return composer.composed

    def __eq__(self, other):
        return self.major == other.major and self.minor == other.minor

    def __lt__(self, other):
        if self.major == other.major:
            return self.minor < other.minor

        return self.major < other. major

    @property
    def major(self):
        return self._major

    @property
    def minor(self):
        return self._minor

    @property
    def supported_versions(self):
        if self.major == SshVersion.SSH1 and self.minor == 99:
            return [SshVersion.SSH1, SshVersion.SSH2]

        return [self.major, ]
