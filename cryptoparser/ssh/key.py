# -*- coding: utf-8 -*-

import abc
import base64
import binascii
import collections
import textwrap

from collections import OrderedDict

import attr
import six

from cryptoparser.common.algorithm import Hash
from cryptoparser.common.base import VariantParsable
from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.common.key import PublicKey
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary

from cryptoparser.ssh.ciphersuite import SshHostKeyAlgorithm


@attr.s
class SshPublicKeyBase(PublicKey):
    host_key_algorithm = attr.ib(
        converter=SshHostKeyAlgorithm,
        validator=attr.validators.instance_of(SshHostKeyAlgorithm)
    )

    _HEADER_SIZE = 4

    @classmethod
    def get_host_key_algorithms(cls):
        raise NotImplementedError()

    @property
    def key_type(self):
        return self.host_key_algorithm.value.authentication

    @property
    @abc.abstractmethod
    def key_size(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def _fingerprint(cls, hash_type, key_bytes, prefix):
        digest = cls.get_digest(hash_type, key_bytes)

        if hash_type == Hash.MD5:
            fingerprint = ':'.join(textwrap.wrap(bytes.decode(binascii.hexlify(digest), 'ascii'), 2))
        else:
            fingerprint = bytes.decode(base64.b64encode(digest), 'ascii')

        return ':'.join((prefix, fingerprint))

    @property
    def fingerprints(self):
        key_bytes = self.key_bytes
        return OrderedDict([
            (hash_type, self._fingerprint(hash_type, key_bytes, prefix))
            for hash_type, prefix in [(Hash.SHA2_256, 'SHA256'), (Hash.SHA1, 'SHA1'), (Hash.MD5, 'MD5')]
        ])

    def _host_key_asdict(self):
        known_hosts = base64.b64encode(self.key_bytes).decode('ascii')

        key_dict = OrderedDict([
            ('known_hosts', known_hosts),
            ('fingerprints', self.fingerprints),
            ('key_type', self.key_type),
            ('key_name', self.host_key_algorithm),
            ('key_size', self.key_size),
        ])

        return key_dict

    def _asdict(self):
        return self._host_key_asdict()

    @classmethod
    def _parse_host_key_algorithm(cls, parsable):
        if len(parsable) < cls._HEADER_SIZE:
            raise NotEnoughData(cls._HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)

        parser.parse_parsable('host_key_algorithm', SshHostKeyAlgorithm, 4)

        if parser['host_key_algorithm'] not in cls.get_host_key_algorithms():
            raise InvalidType()

        return parser

    def _compose_host_key_algorithm(self):
        composer = ComposerBinary()

        host_key_algorithm_bytes = self.host_key_algorithm.compose()
        composer.compose_bytes(host_key_algorithm_bytes, 4)

        return composer


class SshHostKeyBase(SshPublicKeyBase):
    @classmethod
    @abc.abstractmethod
    def get_host_key_algorithms(cls):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def key_size(self):
        raise NotImplementedError()


class SshHostKeyParserBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def _parse_host_key_algorithm(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def _compose_host_key_algorithm(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse_host_key_params(cls, parser):
        raise NotImplementedError()

    @abc.abstractmethod
    def _compose_host_key_params(self, composer):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_host_key_algorithm(parsable)

        cls._parse_host_key_params(parser)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = self._compose_host_key_algorithm()

        self._compose_host_key_params(composer)

        return composer.composed


@attr.s
class SshHostKeyDSSBase(SshHostKeyBase):
    p = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    g = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    q = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    y = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_host_key_algorithms(cls):
        return [
            SshHostKeyAlgorithm.SSH_DSS,
            SshHostKeyAlgorithm.SSH_DSS_SHA224_SSH_COM,
            SshHostKeyAlgorithm.SSH_DSS_SHA256_SSH_COM,
            SshHostKeyAlgorithm.SSH_DSS_SHA384_SSH_COM,
            SshHostKeyAlgorithm.SSH_DSS_SHA512_SSH_COM,
        ]

    @property
    def key_size(self):
        return (len(self.p) - 1) * 8

    @classmethod
    def _parse_host_key_params(cls, parser):
        for param_name in ['p', 'q', 'g', 'y']:
            parser.parse_bytes(param_name, 4)

    def _compose_host_key_params(self, composer):
        for param_name in ['p', 'q', 'g', 'y']:
            value = getattr(self, param_name)
            composer.compose_bytes(value, 4)


@attr.s
class SshHostKeyDSS(SshHostKeyDSSBase, SshHostKeyParserBase):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostKeyRSABase(SshHostKeyBase):
    exponent = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    modulus = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_host_key_algorithms(cls):
        return [
            SshHostKeyAlgorithm.SSH_RSA,
            SshHostKeyAlgorithm.SSH_RSA_SHA224_SSH_COM,
            SshHostKeyAlgorithm.SSH_RSA_SHA256_SSH_COM,
            SshHostKeyAlgorithm.SSH_RSA_SHA384_SSH_COM,
            SshHostKeyAlgorithm.SSH_RSA_SHA512_SSH_COM,
        ]

    @property
    def key_size(self):
        return (len(self.modulus) - 1) * 8

    @classmethod
    def _parse_host_key_params(cls, parser):
        parser.parse_bytes('exponent', 4)
        parser.parse_bytes('modulus', 4)

    def _compose_host_key_params(self, composer):
        composer.compose_bytes(self.exponent, 4)
        composer.compose_bytes(self.modulus, 4)


@attr.s
class SshHostKeyRSA(SshHostKeyRSABase, SshHostKeyParserBase):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostKeyECDSABase(SshHostKeyBase):
    curve_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    curve_data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_host_key_algorithms(cls):
        return [
            SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
            SshHostKeyAlgorithm.ECDSA_SHA2_NISTP384,
            SshHostKeyAlgorithm.ECDSA_SHA2_NISTP521,
        ]

    @property
    def key_size(self):
        return int(self.curve_name[len('nistp'):])

    @classmethod
    def _parse_host_key_params(cls, parser):
        parser.parse_string('curve_name', 4, 'ascii')
        parser.parse_bytes('curve_data', 4)

    def _compose_host_key_params(self, composer):
        composer.compose_string(self.curve_name, 'ascii', 4)
        composer.compose_bytes(self.curve_data, 4)


@attr.s
class SshHostKeyECDSA(SshHostKeyECDSABase, SshHostKeyParserBase):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostKeyEDDSABase(SshHostKeyBase):
    key_data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_host_key_algorithms(cls):
        return [SshHostKeyAlgorithm.SSH_ED25519, ]

    @property
    def key_size(self):
        return len(self.key_data) * 8

    @classmethod
    def _parse_host_key_params(cls, parser):
        parser.parse_bytes('key_data', 4)

    def _compose_host_key_params(self, composer):
        composer.compose_bytes(self.key_data, 4)


@attr.s
class SshHostKeyEDDSA(SshHostKeyEDDSABase, SshHostKeyParserBase):
    @property
    def key_bytes(self):
        return self.compose()


class SshHostPublicKeyVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (SshHostKeyAlgorithm.SSH_ED25519, (SshHostKeyEDDSA, )),
        (SshHostKeyAlgorithm.SSH_RSA, (SshHostKeyRSA, )),
        (SshHostKeyAlgorithm.RSA_SHA2_256, (SshHostKeyRSA, )),
        (SshHostKeyAlgorithm.RSA_SHA2_512, (SshHostKeyRSA, )),
        (SshHostKeyAlgorithm.SSH_DSS, (SshHostKeyDSS, )),
        (SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256, (SshHostKeyECDSA, )),
        (SshHostKeyAlgorithm.ECDSA_SHA2_NISTP384, (SshHostKeyECDSA, )),
        (SshHostKeyAlgorithm.ECDSA_SHA2_NISTP521, (SshHostKeyECDSA, )),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS
