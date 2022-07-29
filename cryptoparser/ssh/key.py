# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import base64
import binascii
import collections
import datetime
import enum
import textwrap

from collections import OrderedDict

import ipaddress
import attr
import six


from cryptoparser.common.algorithm import Hash
from cryptoparser.common.base import (
    FourByteEnumComposer,
    FourByteEnumParsable,
    Serializable,
    StringEnumParsable,
    VariantParsable,
    VectorParamParsable,
    VectorParamString,
    VectorParsable,
    VectorParsableDerived,
    VectorString,
)
from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.common.key import PublicKey
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary, ComposerText

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
            fingerprint = ':'.join(textwrap.wrap(six.ensure_text(binascii.hexlify(digest), 'ascii'), 2))
        else:
            fingerprint = six.ensure_text(base64.b64encode(digest), 'ascii')

        return ':'.join((prefix, fingerprint))

    @property
    def fingerprints(self):
        key_bytes = self.key_bytes
        return OrderedDict([
            (hash_type, self._fingerprint(hash_type, key_bytes, prefix))
            for hash_type, prefix in [(Hash.SHA2_256, 'SHA256'), (Hash.SHA1, 'SHA1'), (Hash.MD5, 'MD5')]
        ])

    def host_key_asdict(self):
        known_hosts = six.ensure_text(base64.b64encode(self.key_bytes), 'ascii')

        key_dict = OrderedDict([
            ('key_type', self.key_type),
            ('key_name', self.host_key_algorithm),
            ('key_size', self.key_size),
            ('fingerprints', self.fingerprints),
            ('known_hosts', known_hosts),
        ])

        return key_dict

    def _asdict(self):
        return self.host_key_asdict()

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
    p = attr.ib(
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'p', 'human_friendly': False},
    )
    g = attr.ib(
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'g', 'human_friendly': False},
    )
    q = attr.ib(
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'q', 'human_friendly': False},
    )
    y = attr.ib(
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'y', 'human_friendly': False},
    )

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
        return (self.p.bit_length() + 7) // 8 * 8

    @classmethod
    def _parse_host_key_params(cls, parser):
        for param_name in ['p', 'q', 'g', 'y']:
            parser.parse_ssh_mpint(param_name)

    def _compose_host_key_params(self, composer):
        for param_name in ['p', 'q', 'g', 'y']:
            value = getattr(self, param_name)
            composer.compose_ssh_mpint(value)

    def host_key_asdict(self):
        key_dict = OrderedDict([])

        key_dict.update(SshHostKeyBase.host_key_asdict(self))
        key_dict.update(OrderedDict([
            (param_name, getattr(self, param_name))
            for param_name in attr.fields_dict(SshHostKeyDSSBase).keys()
        ]))

        return key_dict


@attr.s
class SshHostKeyDSS(SshHostKeyDSSBase, SshHostKeyParserBase):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostKeyRSABase(SshHostKeyBase):
    e = attr.ib(
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'e', 'human_friendly': False},
    )
    n = attr.ib(
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'n', 'human_friendly': False},
    )

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
        return (self.n.bit_length() + 7) // 8 * 8

    @classmethod
    def _parse_host_key_params(cls, parser):
        parser.parse_ssh_mpint('e')
        parser.parse_ssh_mpint('n')

    def _compose_host_key_params(self, composer):
        composer.compose_ssh_mpint(self.e)
        composer.compose_ssh_mpint(self.n)


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


@attr.s(frozen=True)
class SshCertTypeParams(Serializable):
    code = attr.ib(validator=attr.validators.instance_of(int))
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))

    def _as_markdown(self, level):
        return self._markdown_result(self.name, level)


class SshCertType(FourByteEnumComposer, enum.Enum):
    SSH_CERT_TYPE_USER = SshCertTypeParams(code=1, name='User')
    SSH_CERT_TYPE_HOST = SshCertTypeParams(code=2, name='Host')


class SshCertTypeFactory(FourByteEnumParsable):
    @classmethod
    def get_enum_class(cls):
        return SshCertType

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class SshCertSignature(ParsableBase):
    signature_type = attr.ib(validator=attr.validators.instance_of(SshHostKeyAlgorithm))
    signature_data = attr.ib(attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_parsable('signature_type', SshHostKeyAlgorithm, 4)
        parser.parse_bytes('signature_data', 4)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_parsable(self.signature_type, 4)
        composer.compose_bytes(self.signature_data, 4)

        return composer.composed


@attr.s
class SshString(ParsableBase):
    value = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_string('value', 4, 'ascii')

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_string(self.value, 'ascii', 4)

        return composer.composed


class SshCertValidPrincipals(VectorParsable):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=SshString,
            fallback_class=None,
            min_byte_num=0, max_byte_num=2 ** 32 - 4
        )


@attr.s(frozen=True)
class SshCertExtensionParam(object):
    code = attr.ib(validator=attr.validators.instance_of(six.string_types))
    critical = attr.ib(validator=attr.validators.instance_of(bool))


class SshCertExtensionName(StringEnumParsable, enum.Enum):
    FORCE_COMMAND = SshCertExtensionParam(
        code='force-command',
        critical=True,
    )
    SOURCE_ADDRESS = SshCertExtensionParam(
        code='source-address',
        critical=True,
    )
    NO_PRESENCE_REQUIRED = SshCertExtensionParam(
        code='no-presence-required',
        critical=False,
    )
    PERMIT_X11_FORWARDING = SshCertExtensionParam(
        code='permit-X11-forwarding',
        critical=False,
    )
    PERMIT_AGENT_FORWARDING = SshCertExtensionParam(
        code='permit-agent-forwarding',
        critical=False,
    )
    PERMIT_PORT_FORWARDING = SshCertExtensionParam(
        code='permit-port-forwarding',
        critical=False,
    )
    PERMIT_PTY = SshCertExtensionParam(
        code='permit-pty',
        critical=False,
    )
    PERMIT_USER_RC = SshCertExtensionParam(
        code='permit-user-rc',
        critical=False,
    )


class SshCertConstraintVector(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=SshCertExtensionParsed,
            fallback_class=SshCertExtensionUnparsed,
            min_byte_num=0, max_byte_num=2 ** 32 - 1
        )


@attr.s
class SshCertExtensionBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class SshCertExtensionUnparsed(SshCertExtensionBase):
    extension_name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    extension_data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_string('extension_name', 4, 'ascii')
        parser.parse_bytes('extension_data', 4)

        return SshCertExtensionUnparsed(**parser), parser.parsed_length

    def compose(self):
        payload_composer = ComposerBinary()

        payload_composer.compose_string(self.extension_name, 'ascii', 4)
        payload_composer.compose_bytes(self.extension_data, 4)

        return payload_composer.composed_bytes


@attr.s
class SshCertExtensionParsed(SshCertExtensionBase):
    extension_name = attr.ib(init=False, validator=attr.validators.instance_of(SshCertExtensionName))

    def __attrs_post_init__(self):
        self.extension_name = self.get_extension_name()

        attr.validate(self)

    @classmethod
    @abc.abstractmethod
    def get_extension_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        header_parser = ParserBinary(parsable)

        header_parser.parse_parsable('extension_name', SshCertExtensionName, 4)
        if header_parser['extension_name'] != cls.get_extension_name():
            raise InvalidType()

        return header_parser

    def _compose_header(self):
        header_composer = ComposerBinary()

        header_composer.compose_string(self.extension_name.value.code, 'ascii', 4)

        return header_composer


class SshCertExtensionNoData(SshCertExtensionParsed):
    @classmethod
    @abc.abstractmethod
    def get_extension_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable):
        header_parser = super(SshCertExtensionNoData, cls)._parse_header(parsable)

        header_parser.parse_numeric('extension_length', 4)

        return header_parser

    def _compose_header(self):
        header_composer = super(SshCertExtensionNoData, self)._compose_header()

        header_composer.compose_numeric(0, 4)

        return header_composer

    @classmethod
    def _parse(cls, parsable):
        header_parser = cls._parse_header(parsable)

        return cls(), header_parser.parsed_length

    def compose(self):
        header_composer = self._compose_header()

        return header_composer.composed_bytes


class SshCertExtensionNoPrecenseRequired(SshCertExtensionNoData):
    @classmethod
    def get_extension_name(cls):
        return SshCertExtensionName.NO_PRESENCE_REQUIRED


class SshCertExtensionPermitX11Forwarding(SshCertExtensionNoData):
    @classmethod
    def get_extension_name(cls):
        return SshCertExtensionName.PERMIT_X11_FORWARDING


class SshCertExtensionPermitAgentForwarding(SshCertExtensionNoData):
    @classmethod
    def get_extension_name(cls):
        return SshCertExtensionName.PERMIT_AGENT_FORWARDING


class SshCertExtensionPermitPortForwarding(SshCertExtensionNoData):
    @classmethod
    def get_extension_name(cls):
        return SshCertExtensionName.PERMIT_PORT_FORWARDING


class SshCertExtensionPermitPTY(SshCertExtensionNoData):
    @classmethod
    def get_extension_name(cls):
        return SshCertExtensionName.PERMIT_PTY


class SshCertExtensionPermitUserRC(SshCertExtensionNoData):
    @classmethod
    def get_extension_name(cls):
        return SshCertExtensionName.PERMIT_USER_RC


@attr.s
class SshCertExtensionForceCommand(SshCertExtensionParsed):
    command = attr.ib(validator=attr.validators.instance_of(six.string_types))

    @classmethod
    def get_extension_name(cls):
        return SshCertExtensionName.FORCE_COMMAND

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_string('command', 4, 'ascii')

        return cls(parser['command']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_string(self.command, 'ascii', 4)

        header_composer = self._compose_header()

        return header_composer.composed_bytes + body_composer.composed_bytes


class VectorParamNetorkAddress(VectorParamString):
    def get_item_size(self, item):
        return len(str(item))


class NetworkVector(VectorString):
    @classmethod
    def get_param(cls):
        return VectorParamNetorkAddress(
            min_byte_num=0,
            max_byte_num=2 ** 32 - 1,
            separator=',',
            item_class=ipaddress.ip_network,
            fallback_class=None,
        )

    def compose(self):
        composer = ComposerBinary()

        address_composer = ComposerText()
        address_composer.compose_string_array(self._items)

        composer.compose_bytes(address_composer.composed, 4)

        return composer.composed


@attr.s
class SshCertExtensionSourceAddress(SshCertExtensionParsed):
    addresses = attr.ib(
        converter=NetworkVector,
        validator=attr.validators.instance_of(NetworkVector)
    )

    @classmethod
    def get_extension_name(cls):
        return SshCertExtensionName.SOURCE_ADDRESS

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_header(parsable)

        parser.parse_parsable('addresses', NetworkVector)

        return cls(parser['addresses']), parser.parsed_length

    def compose(self):
        composer = self._compose_header()

        composer.compose_parsable(self.addresses)

        return composer.composed_bytes


class SshCertConstraintVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict([
        (SshCertExtensionName.NO_PRESENCE_REQUIRED, (SshCertExtensionNoPrecenseRequired, )),
        (SshCertExtensionName.PERMIT_X11_FORWARDING, (SshCertExtensionPermitX11Forwarding, )),
        (SshCertExtensionName.PERMIT_AGENT_FORWARDING, (SshCertExtensionPermitAgentForwarding, )),
        (SshCertExtensionName.PERMIT_PORT_FORWARDING, (SshCertExtensionPermitPortForwarding, )),
        (SshCertExtensionName.PERMIT_PTY, (SshCertExtensionPermitPTY, )),
        (SshCertExtensionName.PERMIT_USER_RC, (SshCertExtensionPermitUserRC, )),
        (SshCertExtensionName.FORCE_COMMAND, (SshCertExtensionForceCommand, )),
        (SshCertExtensionName.SOURCE_ADDRESS, (SshCertExtensionSourceAddress, )),
    ])

    @classmethod
    @abc.abstractmethod
    def _get_variants(cls):
        raise NotImplementedError()


class SshCertificateBase(object):
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

    def host_key_asdict(self):
        return attr.asdict(self, recurse=False, dict_factory=OrderedDict)


@attr.s
class SshHostCertificateV00Base(ParsableBase, SshCertificateBase):  # pylint: disable=too-many-instance-attributes
    certificate_type = attr.ib(validator=attr.validators.instance_of(SshCertType))
    key_id = attr.ib(
        validator=attr.validators.instance_of(six.string_types),
        metadata={'human_readable_name': 'Key ID'},
    )
    valid_principals = attr.ib(
        converter=SshCertValidPrincipals,
        validator=attr.validators.instance_of(SshCertValidPrincipals)
    )
    valid_after = attr.ib(validator=attr.validators.instance_of(datetime.datetime))
    valid_before = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(datetime.datetime)))
    constraints = attr.ib(
        converter=SshCertConstraintVector,
        validator=attr.validators.instance_of(SshCertConstraintVector)
    )
    nonce = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    reserved = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    signature_key = attr.ib(validator=attr.validators.instance_of(SshPublicKeyBase))
    signature = attr.ib(validator=attr.validators.instance_of(SshCertSignature))

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
    def _parse_host_cert_params(cls, parser):
        parser.parse_parsable('certificate_type', SshCertTypeFactory)
        parser.parse_string('key_id', 4, 'ascii')
        parser.parse_parsable('valid_principals', SshCertValidPrincipals)

        parser.parse_timestamp('valid_after')
        parser.parse_timestamp('valid_before')

        parser.parse_parsable('constraints', SshCertConstraintVector)
        parser.parse_bytes('nonce', 4)
        parser.parse_bytes('reserved', 4)
        parser.parse_parsable('signature_key', SshHostPublicKeyVariant, 4)
        parser.parse_parsable('signature', SshCertSignature, 4)

    def _compose_host_cert_params(self, composer):
        composer.compose_parsable(self.certificate_type)
        composer.compose_string(self.key_id, 'ascii', 4)
        composer.compose_parsable(self.valid_principals)

        composer.compose_timestamp(self.valid_after)
        composer.compose_timestamp(self.valid_before)

        composer.compose_parsable(self.constraints)
        composer.compose_bytes(self.nonce, 4)
        composer.compose_bytes(self.reserved, 4)
        composer.compose_parsable(self.signature_key, 4)
        composer.compose_parsable(self.signature, 4)

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_host_key_algorithm(parsable)

        cls._parse_host_key_params(parser)
        cls._parse_host_cert_params(parser)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = self._compose_host_key_algorithm()

        self._compose_host_key_params(composer)
        self._compose_host_cert_params(composer)

        return composer.composed


class SshHostCertificateBase(object):
    def _asdict(self):
        key_dict = OrderedDict([])

        key_dict.update(SshPublicKeyBase.host_key_asdict(self))
        key_dict.update(SshCertificateBase.host_key_asdict(self))

        return key_dict


@attr.s
class SshHostCertificateV00DSSBase(SshHostCertificateBase, SshHostKeyDSSBase, SshHostCertificateV00Base):
    @property
    def key_bytes(self):
        return self.compose()


class SshHostCertificateV00DSS(SshHostCertificateV00DSSBase, SshHostCertificateV00Base):
    @classmethod
    def get_host_key_algorithms(cls):
        return [SshHostKeyAlgorithm.SSH_DSS_CERT_V00_OPENSSH_COM, ]


@attr.s
class SshHostCertificateV00RSABase(SshHostCertificateBase, SshHostKeyRSABase, SshHostCertificateV00Base):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostCertificateV00RSA(SshHostCertificateV00RSABase, SshHostCertificateV00Base):
    @classmethod
    def get_host_key_algorithms(cls):
        return [SshHostKeyAlgorithm.SSH_RSA_CERT_V00_OPENSSH_COM, ]


class SshCertExtensionVariant(SshCertConstraintVariant):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (constraint_name, constraint_classes)
            for constraint_name, constraint_classes in cls._VARIANTS.items()
            if constraint_name.value.critical is False
        ])


class SshCertExtensionVector(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=SshCertExtensionVariant,
            fallback_class=SshCertExtensionUnparsed,
            min_byte_num=0, max_byte_num=2 ** 32 - 1
        )


class SshCertCriticalOptionVariant(SshCertConstraintVariant):
    @classmethod
    def _get_variants(cls):
        return collections.OrderedDict([
            (constraint_name, constraint_classes)
            for constraint_name, constraint_classes in cls._VARIANTS.items()
            if constraint_name.value.critical is True
        ])


class SshCertCriticalOptionVector(VectorParsableDerived):
    @classmethod
    def get_param(cls):
        return VectorParamParsable(
            item_class=SshCertCriticalOptionVariant,
            fallback_class=SshCertExtensionUnparsed,
            min_byte_num=0, max_byte_num=2 ** 32 - 1
        )


@attr.s
class SshHostCertificateV01Base(ParsableBase, SshCertificateBase):  # pylint: disable=too-many-instance-attributes
    nonce = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    serial = attr.ib(validator=attr.validators.instance_of(six.integer_types))
    certificate_type = attr.ib(validator=attr.validators.instance_of(SshCertType))
    key_id = attr.ib(validator=attr.validators.instance_of(six.string_types))
    valid_principals = attr.ib(
        converter=SshCertValidPrincipals,
        validator=attr.validators.instance_of(SshCertValidPrincipals)
    )
    valid_after = attr.ib(validator=attr.validators.instance_of(datetime.datetime))
    valid_before = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(datetime.datetime)))
    critical_options = attr.ib(
        converter=SshCertCriticalOptionVector,
        validator=attr.validators.instance_of(SshCertCriticalOptionVector)
    )
    extensions = attr.ib(
        converter=SshCertExtensionVector,
        validator=attr.validators.instance_of(SshCertExtensionVector)
    )
    reserved = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    signature_key = attr.ib(validator=attr.validators.instance_of(SshPublicKeyBase))
    signature = attr.ib(
        validator=attr.validators.instance_of(SshCertSignature),
        metadata={'human_friendly': False},
    )

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
    def _parse_host_cert_params(cls, parser):
        parser.parse_numeric('serial', 8)
        parser.parse_parsable('certificate_type', SshCertTypeFactory)
        parser.parse_string('key_id', 4, 'ascii')
        parser.parse_parsable('valid_principals', SshCertValidPrincipals)

        parser.parse_timestamp('valid_after')
        parser.parse_timestamp('valid_before')

        parser.parse_parsable('critical_options', SshCertCriticalOptionVector)
        parser.parse_parsable('extensions', SshCertExtensionVector)
        parser.parse_bytes('reserved', 4)
        parser.parse_parsable('signature_key', SshHostPublicKeyVariant, 4)
        parser.parse_parsable('signature', SshCertSignature, 4)

    def _compose_host_cert_params(self, composer):
        composer.compose_numeric(self.serial, 8)
        composer.compose_parsable(self.certificate_type)
        composer.compose_string(self.key_id, 'ascii', 4)
        composer.compose_parsable(self.valid_principals)

        composer.compose_timestamp(self.valid_after)
        composer.compose_timestamp(self.valid_before)

        composer.compose_parsable(self.critical_options)
        composer.compose_parsable(self.extensions)
        composer.compose_bytes(self.reserved, 4)
        composer.compose_parsable(self.signature_key, 4)
        composer.compose_parsable(self.signature, 4)

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_host_key_algorithm(parsable)

        parser.parse_bytes('nonce', 4)

        cls._parse_host_key_params(parser)
        cls._parse_host_cert_params(parser)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = self._compose_host_key_algorithm()

        composer.compose_bytes(self.nonce, 4)

        self._compose_host_key_params(composer)
        self._compose_host_cert_params(composer)

        return composer.composed


@attr.s
class SshHostCertificateV01DSSBase(SshHostCertificateBase, SshHostKeyDSSBase, SshHostCertificateV01Base):
    @property
    def key_bytes(self):
        return self.compose()


class SshHostCertificateV01DSS(SshHostCertificateV01DSSBase, SshHostCertificateV01Base):
    @classmethod
    def get_host_key_algorithms(cls):
        return [SshHostKeyAlgorithm.SSH_DSS_CERT_V01_OPENSSH_COM, ]


@attr.s
class SshHostCertificateV01RSABase(SshHostCertificateBase, SshHostKeyRSABase, SshHostCertificateV01Base):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostCertificateV01RSA(SshHostCertificateV01RSABase, SshHostCertificateV01Base):
    @classmethod
    def get_host_key_algorithms(cls):
        return [SshHostKeyAlgorithm.SSH_RSA_CERT_V01_OPENSSH_COM, ]


@attr.s
class SshHostCertificateV01ECDSABase(SshHostCertificateBase, SshHostKeyECDSABase, SshHostCertificateV01Base):
    @property
    def key_bytes(self):
        return self.compose()


class SshHostCertificateV01ECDSA(SshHostCertificateV01ECDSABase, SshHostCertificateV01Base):
    @classmethod
    def get_host_key_algorithms(cls):
        return [
            SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM,
            SshHostKeyAlgorithm.ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM,
            SshHostKeyAlgorithm.ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM,
        ]


@attr.s
class SshHostCertificateV01EDDSABase(SshHostCertificateBase, SshHostKeyEDDSABase, SshHostCertificateV01Base):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostCertificateV01EDDSA(SshHostCertificateV01EDDSABase, SshHostCertificateV01Base):
    @classmethod
    def get_host_key_algorithms(cls):
        return [SshHostKeyAlgorithm.SSH_ED25519_CERT_V01_OPENSSH_COM, ]


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
        (SshHostKeyAlgorithm.SSH_DSS_CERT_V00_OPENSSH_COM, (SshHostCertificateV00DSS, )),
        (SshHostKeyAlgorithm.SSH_RSA_CERT_V00_OPENSSH_COM, (SshHostCertificateV00RSA, )),
        (SshHostKeyAlgorithm.SSH_DSS_CERT_V01_OPENSSH_COM, (SshHostCertificateV01DSS, )),
        (SshHostKeyAlgorithm.SSH_RSA_CERT_V01_OPENSSH_COM, (SshHostCertificateV01RSA, )),
        (SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256_CERT_V01_OPENSSH_COM, (SshHostCertificateV01ECDSA, )),
        (SshHostKeyAlgorithm.ECDSA_SHA2_NISTP384_CERT_V01_OPENSSH_COM, (SshHostCertificateV01ECDSA, )),
        (SshHostKeyAlgorithm.ECDSA_SHA2_NISTP521_CERT_V01_OPENSSH_COM, (SshHostCertificateV01ECDSA, )),
        (SshHostKeyAlgorithm.SSH_ED25519_CERT_V01_OPENSSH_COM, (SshHostCertificateV01EDDSA, )),
    ])

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS
