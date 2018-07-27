#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum

import six

from cryptoparser.common.base import JSONSerializable
from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary


class TlsVersion(enum.IntEnum):
    SSL3 = 0x00
    TLS1_0 = 0x01
    TLS1_1 = 0x02
    TLS1_2 = 0x03
    TLS1_3 = 0x04


@six.add_metaclass(abc.ABCMeta)
class TlsProtocolVersionBase(JSONSerializable, ParsableBase):
    _SIZE = 2

    def __init__(self, major, minor):
        self._major = None
        self._minor = None

        self.major = major
        self.minor = minor

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls._SIZE:
            raise NotEnoughData(bytes_needed=cls._SIZE)

        parser = ParserBinary(parsable)

        parser.parse_numeric('major', 1)
        parser.parse_numeric('minor', 1)

        for subclass in TlsProtocolVersionBase.__subclasses__():
            try:
                version = subclass.__new__(subclass)
                version.major = parser['major']
                version.minor = parser['minor']
            except InvalidValue:
                pass
            else:
                return version, cls._SIZE

        raise InvalidValue(parsable[:cls._SIZE], cls)

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.major, 1)
        composer.compose_numeric(self.minor, 1)

        return composer.composed_bytes

    def __eq__(self, other):
        return self.major == other.major and self.minor == other.minor

    def __lt__(self, other):
        if self.major == other.major:
            return self.minor < other.minor

        return isinstance(self, TlsProtocolVersionDraft) == (other.minor == TlsVersion.TLS1_3)

    @property
    def major(self):
        return self._major

    @major.setter
    @abc.abstractproperty
    def major(self, value):
        raise NotImplementedError()

    @property
    def minor(self):
        return self._minor

    @minor.setter
    @abc.abstractmethod
    def minor(self, value):
        raise NotImplementedError()


class TlsProtocolVersionFinal(TlsProtocolVersionBase):
    _MAJOR = 0x03

    def __init__(self, tls_version):
        # type: (TlsVersion) -> None
        super(TlsProtocolVersionFinal, self).__init__(self._MAJOR, tls_version)

    # pylint: disable=no-member
    @TlsProtocolVersionBase.major.setter
    def major(self, value):
        # type: (int) -> None
        if value != self._MAJOR:
            raise InvalidValue(value, TlsProtocolVersionFinal, 'major')

        self._major = value

    @TlsProtocolVersionBase.minor.setter
    def minor(self, value):
        # type: (TlsVersion) -> None
        try:
            TlsVersion(value)
        except ValueError as e:
            raise InvalidValue(e.args[0], TlsProtocolVersionFinal)

        self._minor = value


class TlsProtocolVersionDraft(TlsProtocolVersionBase):
    _MAJOR = 0x7f
    MAX_DRAFT_NUMBER = 0xff

    def __init__(self, draft_number):
        # type: (int) -> None
        super(TlsProtocolVersionDraft, self).__init__(self._MAJOR, draft_number)

    # pylint: disable=no-member
    @TlsProtocolVersionBase.major.setter
    def major(self, value):
        # type: (int) -> None
        if value != self._MAJOR:
            raise InvalidValue(value, TlsProtocolVersionFinal, 'major')

        self._major = value

    @TlsProtocolVersionBase.minor.setter
    def minor(self, value):
        # type: (int) -> None
        if value > 0xff:
            raise InvalidValue(value, TlsProtocolVersionDraft, 'draft number')
        if value < 0x00:
            raise InvalidValue(value, TlsProtocolVersionDraft, 'draft number')

        self._minor = value


class SslVersion(enum.IntEnum):
    SSL2 = 0x0002

@six.add_metaclass(abc.ABCMeta)
class SslProtocolVersion(JSONSerializable, ParsableBase):
    _SIZE = 2

    def __eq__(self, other):
        return isinstance(other, SslProtocolVersion)

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls._SIZE:
            raise NotEnoughData(bytes_needed=cls._SIZE)

        parser = ParserBinary(parsable)

        parser.parse_numeric('version', sl._SIZE, SslVersion)

        return SslProtocolVersion, cls._SIZE

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(SslVersion.SSL2.value, self._SIZE)

        return composer.composed_bytes
