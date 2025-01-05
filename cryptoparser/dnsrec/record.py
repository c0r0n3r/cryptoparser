# -*- coding: utf-8 -*-

import abc
import collections
import datetime
import enum

import attr

from cryptodatahub.common.algorithm import Authentication, NamedGroup, Signature
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.key import (
    PublicKey,
    PublicKeyParamsDsa,
    PublicKeyParamsEcdsa,
    PublicKeyParamsEddsa,
    PublicKeyParamsRsa,
)

from cryptodatahub.dnsrec.algorithm import DnsRrType, DnsSecAlgorithm, DnsSecDigestType

from cryptoparser.common.base import NumericRangeParsableBase, OneByteEnumParsable, Serializable, TwoByteEnumParsable
from cryptoparser.common.exception import NotEnoughData
from cryptoparser.common.parse import ByteOrder, ComposerBinary, ParsableBase, ParserBinary


class DnsSecProtocol(enum.Enum):
    V3 = 3


class DnsSecFlag(enum.IntEnum):
    SECURE_ENTRY_POINT = 0x0001
    REVOKE = 0x0080
    DNS_ZONE_KEY = 0x0100


class DnsSecAlgorithmFactory(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return DnsSecAlgorithm

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class DnsRecordDnskey(ParsableBase, Serializable):
    HEADER_SIZE = 4

    flags = attr.ib(validator=attr.validators.deep_iterable(attr.validators.instance_of(DnsSecFlag)))
    algorithm = attr.ib(validator=attr.validators.instance_of(DnsSecAlgorithm))
    key = attr.ib(validator=attr.validators.instance_of(PublicKey))
    protocol = attr.ib(validator=attr.validators.instance_of(DnsSecProtocol))

    def __attrs_post_init__(self):
        if not isinstance(self.algorithm.value.algorithm, Signature):
            raise InvalidValue(self.algorithm.value.algorithm, type(self), 'algorithm_type')

        algorithm_key_type = self.algorithm.value.algorithm.value.key_type
        algorithm_incompatible = self.key.key_type != algorithm_key_type
        algorithm_compatible_gost = (
            self.algorithm == DnsSecAlgorithm.ECCGOST and
            self.key.key_type == Authentication.ECDSA and
            self.key.params.named_group == NamedGroup.GC256B
        )
        if (algorithm_incompatible and not algorithm_compatible_gost):
            raise InvalidValue(algorithm_key_type, type(self), 'key_type')

    @property
    def key_tag(self):
        if self.algorithm == DnsSecAlgorithm.RSAMD5:
            return (self.key.params.modulus & 0xffffff) >> 8

        key_tag = 0
        parser = ParserBinary(self.compose(), byte_order=ByteOrder.BIG_ENDIAN)

        while parser.unparsed_length > 1:
            parser.parse_numeric('value', 2)
            key_tag += parser['value']
        if parser.unparsed_length:
            parser.parse_numeric('value', 1)
            key_tag += parser['value']

        key_tag += (key_tag >> 16) & 0xffff
        return key_tag & 0xffff

    def _asdict(self):
        dict_value = super()._asdict()
        return collections.OrderedDict([('key_tag', self.key_tag)] + list(dict_value.items()))

    @classmethod
    def _parse_public_key_rsa(cls, key_parser):
        key_parser.parse_numeric('exponent_length_one_octet', 1)
        exponent_length = key_parser['exponent_length_one_octet']
        if exponent_length == 0:
            key_parser.parse_numeric('exponent_length_two_octets', 2)
            exponent_length = key_parser['exponent_length_two_octets']
        key_parser.parse_mpint('public_exponent', exponent_length)
        key_parser.parse_mpint('modulus', key_parser.unparsed_length)

        return PublicKey.from_params(PublicKeyParamsRsa(
            public_exponent=key_parser['public_exponent'],
            modulus=key_parser['modulus'],
        ))

    @classmethod
    def _parse_public_key_ecdsa(cls, dnssec_algorithm, key_parser):
        if dnssec_algorithm == DnsSecAlgorithm.ECDSAP256SHA256:
            named_group = NamedGroup.SECP256K1
        elif dnssec_algorithm == DnsSecAlgorithm.ECDSAP384SHA384:
            named_group = NamedGroup.SECP384R1
        elif dnssec_algorithm == DnsSecAlgorithm.ECCGOST:
            named_group = NamedGroup.GC256B
        else:
            raise NotImplementedError(dnssec_algorithm)

        key_size = named_group.value.size // 8
        key_parser.parse_mpint('x', key_size)
        key_parser.parse_mpint('y', key_size)

        return PublicKey.from_params(PublicKeyParamsEcdsa(
            point_x=key_parser['x'], point_y=key_parser['y'], named_group=named_group,
        ))

    @classmethod
    def _parse_public_key_eddsa(cls, dnssec_algorithm, key_parser):
        if dnssec_algorithm == DnsSecAlgorithm.ED25519:
            curve_type = NamedGroup.CURVE25519
            key_parser.parse_raw('public_key', 256 // 8)
        elif dnssec_algorithm == DnsSecAlgorithm.ED448:
            curve_type = NamedGroup.CURVE448
            key_parser.parse_raw('public_key', 448 // 8)
        else:
            raise NotImplementedError(dnssec_algorithm)

        return PublicKey.from_params(PublicKeyParamsEddsa(
            curve_type=curve_type, key_data=key_parser['public_key']
        ))

    @classmethod
    def _parse_public_key_dss(cls, key_parser):
        key_parser.parse_numeric('t', 1)
        key_parser.parse_mpint('q', 20)

        mpint_length = 64 + key_parser['t'] * 8
        key_parser.parse_mpint('p', mpint_length)
        key_parser.parse_mpint('g', mpint_length)
        key_parser.parse_mpint('y', mpint_length)

        return PublicKey.from_params(PublicKeyParamsDsa(
            prime=key_parser['p'],
            generator=key_parser['g'],
            order=key_parser['q'],
            public_key_value=key_parser['y'],
        ))

    @classmethod
    def parse_key(cls, parsable, dnssec_algorithm):
        key_parser = ParserBinary(parsable)

        public_key_type = dnssec_algorithm.value.algorithm.value.key_type
        if public_key_type == Authentication.RSA:
            public_key = cls._parse_public_key_rsa(key_parser)
        elif public_key_type in [Authentication.ECDSA, Authentication.GOST_R3410_01]:
            public_key = cls._parse_public_key_ecdsa(dnssec_algorithm, key_parser)
        elif public_key_type == Authentication.EDDSA:
            public_key = cls._parse_public_key_eddsa(dnssec_algorithm, key_parser)
        elif public_key_type == Authentication.DSS:
            public_key = cls._parse_public_key_dss(key_parser)
        else:
            raise NotImplementedError(dnssec_algorithm)

        return public_key

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric_flags('flags', 2, DnsSecFlag)
        parser.parse_numeric('protocol', 1, DnsSecProtocol)

        parser.parse_parsable('algorithm', DnsSecAlgorithmFactory)
        parser.parse_raw('key', parser.unparsed_length)

        public_key = cls.parse_key(parser['key'], parser['algorithm'])

        return cls(
            parser['flags'],
            parser['algorithm'],
            public_key,
            parser['protocol'],
        ), parser.parsed_length

    @staticmethod
    def _compose_public_key_rsa(key_composer, key):
        key_params = key.params
        exponent_length = (key_params.public_exponent.bit_length() + 7) // 8
        if exponent_length > 255:
            key_composer.compose_numeric(0, 1)
            key_composer.compose_numeric(exponent_length, 2)
        else:
            key_composer.compose_numeric(exponent_length, 1)

        key_composer.compose_mpint(key_params.public_exponent, exponent_length)
        key_composer.compose_mpint(key_params.modulus, key.key_size // 8)

    @staticmethod
    def _compose_public_key_ecdsa(key_composer, key):
        key_params = key.params
        key_size = key.key_size // 8
        key_composer.compose_mpint(key_params.point_x, key_size)
        key_composer.compose_mpint(key_params.point_y, key_size)

    @staticmethod
    def _compose_public_key_eddsa(key_composer, key):
        key_params = key.params
        key_composer.compose_raw(key_params.key_data)

    @staticmethod
    def _compose_public_key_dss(key_composer, key):
        key_params = key.params
        key_size = key.key_size // 8

        key_composer.compose_numeric((key_size - 64) // 8, 1)
        key_composer.compose_mpint(key_params.order, 20)

        key_composer.compose_mpint(key_params.prime, key_size)
        key_composer.compose_mpint(key_params.generator, key_size)
        key_composer.compose_mpint(key_params.public_key_value, key_size)

    @staticmethod
    def compose_key(key):
        key_composer = ComposerBinary()
        public_key_type = key.key_type

        if public_key_type == Authentication.RSA:
            DnsRecordDnskey._compose_public_key_rsa(key_composer, key)
        elif public_key_type in [Authentication.ECDSA, Authentication.GOST_R3410_01]:
            DnsRecordDnskey._compose_public_key_ecdsa(key_composer, key)
        elif public_key_type == Authentication.EDDSA:
            DnsRecordDnskey._compose_public_key_eddsa(key_composer, key)
        elif public_key_type == Authentication.DSS:
            DnsRecordDnskey._compose_public_key_dss(key_composer, key)
        else:
            raise NotImplementedError(public_key_type)

        return key_composer.composed_bytes

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric_flags(self.flags, 2)
        composer.compose_numeric(self.protocol.value, 1)

        composer.compose_numeric_enum_coded(self.algorithm)

        key_bytes = self.compose_key(self.key)

        return composer.composed_bytes + key_bytes


class DnsSecDigestTypeFactory(OneByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return DnsSecDigestType

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class DnsRecordDs(ParsableBase):
    HEADER_SIZE = 4

    key_tag = attr.ib(validator=attr.validators.instance_of(int))
    algorithm = attr.ib(validator=attr.validators.instance_of(DnsSecAlgorithm))
    digest_type = attr.ib(validator=attr.validators.instance_of(DnsSecDigestType))
    digest = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric('key_tag', 2)
        parser.parse_parsable('algorithm', DnsSecAlgorithmFactory)
        parser.parse_parsable('digest_type', DnsSecDigestTypeFactory)
        parser.parse_raw('digest', parser.unparsed_length)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.key_tag, 2)
        composer.compose_numeric_enum_coded(self.algorithm)
        composer.compose_numeric_enum_coded(self.digest_type)
        composer.compose_raw(self.digest)

        return composer.composed_bytes


class DnsRrTypeFactory(TwoByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return DnsRrType

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class DnsRrTypePrivate(NumericRangeParsableBase):
    @classmethod
    def _get_value_min(cls):
        return 0xff00

    @classmethod
    def _get_value_max(cls):
        return 0xfffe

    @classmethod
    def _get_value_length(cls):
        return 2


@attr.s
class DnsNameUncompressed(ParsableBase, Serializable):
    labels = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(str))
    )

    def __str__(self):
        return '.'.join(self.labels)

    def _as_markdown(self, level):
        return self._markdown_result(str(self), level)

    @classmethod
    def convert(cls, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, str):
            if not value:
                return cls([])

            return cls(value.split('.'))

        raise InvalidValue(value, cls, 'labels')

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        labels = []
        while True:
            parser.parse_string('label', 1, encoding='idna')
            label = parser['label']

            if not label:
                break

            labels.append(label)

        return cls(labels), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        for label in self.labels:
            composer.compose_string(label, 'idna', 1)

        composer.compose_numeric(0, 1)

        return composer.composed_bytes


@attr.s
class DnsRecordRrsig(ParsableBase):  # pylint: disable=too-many-instance-attributes
    HEADER_SIZE = 24

    type_covered = attr.ib(validator=attr.validators.instance_of((DnsRrType, DnsRrTypePrivate)))
    algorithm = attr.ib(validator=attr.validators.instance_of(DnsSecAlgorithm))
    labels = attr.ib(validator=attr.validators.instance_of(int))
    original_ttl = attr.ib(
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'Original TTL'}
    )
    signature_expiration = attr.ib(validator=attr.validators.instance_of(datetime.datetime))
    signature_inception = attr.ib(validator=attr.validators.instance_of(datetime.datetime))
    key_tag = attr.ib(validator=attr.validators.instance_of(int))
    signers_name = attr.ib(
        converter=DnsNameUncompressed.convert,
        validator=attr.validators.instance_of(DnsNameUncompressed)
    )
    signature = attr.ib(
        validator=attr.validators.instance_of((bytes, bytearray)),
        metadata={'human_friendly': False}
    )

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        try:
            parser.parse_parsable('type_covered', DnsRrTypeFactory)
        except InvalidValue:
            parser.parse_parsable('type_covered', DnsRrTypePrivate)
        parser.parse_parsable('algorithm', DnsSecAlgorithmFactory)
        parser.parse_numeric('labels', 1)
        parser.parse_numeric('original_ttl', 4)
        parser.parse_timestamp('signature_expiration', item_size=4)
        parser.parse_timestamp('signature_inception', item_size=4)
        parser.parse_numeric('key_tag', 2)
        parser.parse_parsable('signers_name', DnsNameUncompressed)
        parser.parse_raw('signature', parser.unparsed_length)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        if isinstance(self.type_covered, DnsRrType):
            composer.compose_numeric_enum_coded(self.type_covered)
        else:
            composer.compose_parsable(self.type_covered)
        composer.compose_numeric_enum_coded(self.algorithm)
        composer.compose_numeric(self.labels, 1)
        composer.compose_numeric(self.original_ttl, 4)
        composer.compose_timestamp(self.signature_expiration, item_size=4)
        composer.compose_timestamp(self.signature_inception, item_size=4)
        composer.compose_numeric(self.key_tag, 2)
        composer.compose_parsable(self.signers_name)
        composer.compose_raw(self.signature)

        return composer.composed_bytes


@attr.s
class DnsRecordMx(ParsableBase):
    HEADER_SIZE = 2

    priority = attr.ib(validator=attr.validators.instance_of(int))
    exchange = attr.ib(
        converter=DnsNameUncompressed.convert,
        validator=attr.validators.instance_of(DnsNameUncompressed)
    )

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_numeric('priority', 2)
        parser.parse_parsable('exchange', DnsNameUncompressed)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(self.priority, 2)
        composer.compose_parsable(self.exchange)

        return composer.composed_bytes


@attr.s
class DnsRecordTxt(ParsableBase):
    HEADER_SIZE = 1

    value = attr.ib(validator=attr.validators.instance_of(str))

    @classmethod
    def _parse(cls, parsable):
        if len(parsable) < cls.HEADER_SIZE:
            raise NotEnoughData(cls.HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)
        value = ''

        while parser.unparsed_length:
            parser.parse_string('value', 1, encoding='ascii')
            value += parser['value']

        return cls(value), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_string(self.value, 'ascii', 1)

        return composer.composed_bytes
