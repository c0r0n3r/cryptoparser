#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import collections
import enum
import six

import attr

from cryptoparser.common.base import ProtocolVersionBase, Serializable, VariantParsable
from cryptoparser.common.exception import InvalidType, InvalidValue
from cryptoparser.common.parse import ParsableBase, ParserText, ComposerText


class SshVersion(enum.IntEnum):
    SSH1 = 1
    SSH2 = 2


@attr.s(hash=True)
class SshProtocolVersion(ProtocolVersionBase):
    major = attr.ib(converter=SshVersion, validator=attr.validators.instance_of(SshVersion))
    minor = attr.ib(validator=attr.validators.instance_of(int), default=0)

    def __str__(self):
        return 'SSH {}.{}'.format(self.major, self.minor)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        try:
            parser.parse_numeric('major')
            parser.parse_separator('.')
            parser.parse_numeric('minor')
        except InvalidValue as e:
            six.raise_from(InvalidValue(parsable, SshProtocolVersion), e)

        return SshProtocolVersion(parser['major'], parser['minor']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_numeric(self.major.value)
        composer.compose_separator('.')
        composer.compose_numeric(self.minor)

        return composer.composed

    @property
    def identifier(self):
        return 'ssh{}'.format(self.major)

    @property
    def supported_versions(self):
        if self.major == SshVersion.SSH1 and self.minor == 99:
            return [SshVersion.SSH1, SshVersion.SSH2]

        return [self.major, ]


class SshSoftwareVersionBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class SshSoftwareVersionUnparsed(SshSoftwareVersionBase, Serializable):
    raw = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @raw.validator
    def raw_validator(self, _, value):  # pylint: disable=no-self-use
        if '\r' in value or '\n' in value or ' ' in value:
            raise InvalidValue(value, SshSoftwareVersionUnparsed, 'raw')
        try:
            value.encode('ascii')
        except UnicodeEncodeError as e:
            six.raise_from(InvalidValue(value, SshSoftwareVersionUnparsed, 'raw'), e)

    def _as_markdown(self, level):
        return self._markdown_result(self.raw, level)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_by_length('raw', len(parsable))

        return SshSoftwareVersionUnparsed(parser['raw']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.raw)

        return composer.composed


@attr.s
class SshSoftwareVersionParsedBase(SshSoftwareVersionBase):
    version = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))

    @classmethod
    @abc.abstractmethod
    def _get_vendor(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_version_separator(cls):
        raise NotImplementedError()

    @property
    def vendor(self):
        return self._get_vendor()

    def _asdict(self):
        return collections.OrderedDict([
            ('vendor', self.vendor),
            ('version', self.version),
        ])

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        version_separator = cls._get_version_separator()
        if version_separator is None:
            parser.parse_string_by_length('vendor')
        else:
            parser.parse_string_until_separator_or_end('vendor', version_separator)

        if parser['vendor'] != cls._get_vendor():
            raise InvalidType()

        if parser.unparsed_length > 0 and version_separator is not None:
            parser.parse_separator(version_separator)
            parser.parse_string_by_length('version')
            version = parser['version']
        else:
            version = None

        return cls(version), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.vendor)
        if self.version is not None:
            composer.compose_separator(self._get_version_separator())
            composer.compose_string(self.version)

        return composer.composed


@attr.s
class SshSoftwareVersionCryptlib(SshSoftwareVersionParsedBase):
    @classmethod
    def _get_vendor(cls):
        return 'cryptlib'

    @classmethod
    def _get_version_separator(cls):
        return None


@attr.s
class SshSoftwareVersionDropbear(SshSoftwareVersionParsedBase):
    @classmethod
    def _get_vendor(cls):
        return 'dropbear'

    @classmethod
    def _get_version_separator(cls):
        return '_'


@attr.s
class SshSoftwareVersionIPSSH(SshSoftwareVersionParsedBase):
    @classmethod
    def _get_vendor(cls):
        return 'IPSSH'

    @classmethod
    def _get_version_separator(cls):
        return '-'


@attr.s
class SshSoftwareVersionMonacaSSH(SshSoftwareVersionParsedBase):
    @classmethod
    def _get_vendor(cls):
        return 'Monaca'

    @classmethod
    def _get_version_separator(cls):
        return None


@attr.s
class SshSoftwareVersionOpenSSH(SshSoftwareVersionParsedBase):
    @classmethod
    def _get_vendor(cls):
        return 'OpenSSH'

    @classmethod
    def _get_version_separator(cls):
        return '_'


class SshSoftwareVersionParsedVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (SshSoftwareVersionCryptlib, (SshSoftwareVersionCryptlib, )),
        (SshSoftwareVersionDropbear, (SshSoftwareVersionDropbear, )),
        (SshSoftwareVersionIPSSH, (SshSoftwareVersionIPSSH, )),
        (SshSoftwareVersionMonacaSSH, (SshSoftwareVersionMonacaSSH, )),
        (SshSoftwareVersionOpenSSH, (SshSoftwareVersionOpenSSH, )),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS
