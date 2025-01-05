# -*- coding: utf-8 -*-

import abc
import functools

import attr

from cryptodatahub.common.grade import Grade, GradeableSimple
from cryptodatahub.tls.version import TlsVersion

from cryptoparser.common.base import TwoByteEnumParsable, ProtocolVersionBase
from cryptoparser.common.parse import ParserBinary, ComposerBinary


class TlsVersionFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return TlsVersion

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s(order=False, eq=False, hash=True)
@functools.total_ordering
class TlsProtocolVersion(ProtocolVersionBase, GradeableSimple):
    version = attr.ib(validator=attr.validators.instance_of(TlsVersion))

    @property
    def grade(self):
        if self.version in (TlsVersion.TLS1_3, TlsVersion.TLS1_2):
            return Grade.SECURE
        if self.version in (TlsVersion.TLS1, TlsVersion.TLS1_1) or self.is_draft or self.is_google_experimental:
            return Grade.DEPRECATED
        if self.version in (TlsVersion.SSL2, TlsVersion.SSL3):
            return Grade.INSECURE

        raise NotImplementedError(self.version)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_parsable('version', TlsVersionFactory)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.major, 1)
        composer.compose_numeric(self.minor, 1)

        return composer.composed_bytes

    @property
    def major(self):
        return (self.version.value.code & 0xff00) >> 8

    @property
    def minor(self):
        return self.version.value.code & 0x00ff

    @property
    def is_draft(self):
        return self.major == 0x7f

    @property
    def is_google_experimental(self):
        return self.major == 0x7e

    def __eq__(self, other):
        return self.version.value.code == other.version.value.code

    def __lt__(self, other):
        if self.major == other.major:
            return self.minor < other.minor
        if self.is_draft:
            return other.version == TlsVersion.TLS1_3
        if other.is_draft:
            return self.version != TlsVersion.TLS1_3

        return self.major < other.major

    @property
    def identifier(self):
        return self.version.name.lower()

    def __str__(self):
        if self.is_draft:
            return f'TLS 1.3 Draft {self.minor}'
        if self.is_google_experimental:
            return f'TLS 1.3 Google Experiment {self.minor}'
        if self.version == TlsVersion.SSL3:
            return 'SSL 3.0'
        if self.version == TlsVersion.SSL2:
            return 'SSL 2.0'

        return f'TLS 1.{self.minor - 1}'

    def _as_markdown(self, level):
        return self._markdown_result(str(self), level)

    def _asdict(self):
        return self.identifier
