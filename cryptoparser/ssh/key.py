# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import base64
import binascii
import collections
import datetime
import enum
import itertools
import textwrap

from collections import OrderedDict

import ipaddress
import attr


from cryptodatahub.common.algorithm import Authentication, Hash, NamedGroup
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.key import (
    PublicKey,
    PublicKeyParamsDsa,
    PublicKeyParamsEcdsa,
    PublicKeyParamsEddsa,
    PublicKeyParamsRsa,
)
from cryptodatahub.common.utils import hash_bytes
from cryptodatahub.ssh.algorithm import SshHostKeyAlgorithm, SshHostKeyType, SshEllipticCurveIdentifier

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
from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary, ComposerText
from cryptoparser.common.x509 import PublicKeyX509


@attr.s
class SshPublicKeyBase():
    host_key_algorithm = attr.ib(
        converter=SshHostKeyAlgorithm,
        validator=attr.validators.instance_of(SshHostKeyAlgorithm)
    )
    public_key = attr.ib(
        validator=attr.validators.instance_of(PublicKey)
    )

    _HEADER_SIZE = 4

    @classmethod
    def get_host_key_algorithms(cls):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def _fingerprint(cls, hash_type, key_bytes, prefix):
        digest = hash_bytes(hash_type, key_bytes)

        if hash_type == Hash.MD5:
            fingerprint = ':'.join(textwrap.wrap(binascii.hexlify(digest).decode('ascii'), 2))
        else:
            fingerprint = base64.b64encode(digest).decode('ascii')

        return ':'.join((prefix, fingerprint))

    @property
    def fingerprints(self):
        key_bytes = self.key_bytes
        return OrderedDict([
            (hash_type, self._fingerprint(hash_type, key_bytes, prefix))
            for hash_type, prefix in [(Hash.SHA2_256, 'SHA256'), (Hash.SHA1, 'SHA1'), (Hash.MD5, 'MD5')]
        ])

    def host_key_asdict(self):
        known_hosts = base64.b64encode(self.key_bytes).decode('ascii')

        public_key_dict = (
            [('key_type', self.host_key_algorithm.value.key_type.value)] +
            list(self.public_key._asdict().items()) +
            [('known_hosts', known_hosts)]
        )

        public_key_dict = OrderedDict(public_key_dict)
        public_key_dict['fingerprints'] = self.fingerprints

        return public_key_dict

    def _asdict(self):
        return self.host_key_asdict()

    @classmethod
    def _parse_host_key_algorithm(cls, parsable):
        if len(parsable) < cls._HEADER_SIZE:
            raise NotEnoughData(cls._HEADER_SIZE - len(parsable))

        parser = ParserBinary(parsable)
        parser.parse_string('host_key_algorithm', 4, 'ascii', SshHostKeyAlgorithm.from_code)

        if parser['host_key_algorithm'] not in cls.get_host_key_algorithms():
            raise InvalidType()

        return parser

    def _compose_host_key_algorithm(self):
        composer = ComposerBinary()

        host_key_algorithm_bytes = self.host_key_algorithm.value.code.encode('ascii')
        composer.compose_bytes(host_key_algorithm_bytes, 4)

        return composer


class SshHostKeyBase(SshPublicKeyBase):
    @classmethod
    @abc.abstractmethod
    def get_host_key_algorithms(cls):
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
    def _parse_host_key(cls, parser):
        raise NotImplementedError()

    @abc.abstractmethod
    def _compose_host_key_params(self, composer):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_host_key_algorithm(parsable)
        host_key = cls._parse_host_key(parser)

        return cls(parser['host_key_algorithm'], host_key), parser.parsed_length

    def compose(self):
        composer = self._compose_host_key_algorithm()

        self._compose_host_key_params(composer)

        return composer.composed


@attr.s
class SshHostKeyDSSBase(SshHostKeyBase):
    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_host_key_algorithms(cls):
        return filter(
            lambda host_key_algorithm: (
                host_key_algorithm.value.key_type == SshHostKeyType.HOST_KEY and
                host_key_algorithm.value.signature.value.key_type == Authentication.DSS
            ),
            SshHostKeyAlgorithm
        )

    @classmethod
    def _parse_host_key(cls, parser):
        for param_name in ['p', 'q', 'g', 'y']:
            parser.parse_ssh_mpint(param_name)

        public_key = PublicKey.from_params(PublicKeyParamsDsa(
            prime=parser['p'],
            generator=parser['g'],
            order=parser['q'],
            public_key_value=parser['y'],
        ))

        for param_name in ['p', 'q', 'g', 'y']:
            del parser[param_name]

        return public_key

    def _compose_host_key_params(self, composer):
        params = self.public_key.params
        for param_name in ['prime', 'order', 'generator', 'public_key_value']:
            value = getattr(params, param_name)
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
    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_host_key_algorithms(cls):
        return filter(
            lambda host_key_algorithm: (
                host_key_algorithm.value.key_type == SshHostKeyType.HOST_KEY and
                host_key_algorithm.value.signature.value.key_type == Authentication.RSA
            ),
            SshHostKeyAlgorithm
        )

    @classmethod
    def _parse_host_key(cls, parser):
        parser.parse_ssh_mpint('e')
        parser.parse_ssh_mpint('n')

        public_key = PublicKey.from_params(PublicKeyParamsRsa(
            modulus=parser['n'],
            public_exponent=parser['e'],
        ))

        del parser['e']
        del parser['n']

        return public_key

    def _compose_host_key_params(self, composer):
        params = self.public_key.params

        composer.compose_ssh_mpint(params.public_exponent)
        composer.compose_ssh_mpint(params.modulus)


@attr.s
class SshHostKeyRSA(SshHostKeyRSABase, SshHostKeyParserBase):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostKeyECDSABase(SshHostKeyBase):
    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_host_key_algorithms(cls):
        return filter(
            lambda host_key_algorithm: (
                host_key_algorithm.value.key_type == SshHostKeyType.HOST_KEY and
                host_key_algorithm.value.signature.value.key_type == Authentication.ECDSA
            ),
            SshHostKeyAlgorithm
        )

    @classmethod
    def _parse_host_key(cls, parser):
        parser.parse_string('curve_identifier', 4, 'ascii', SshEllipticCurveIdentifier.from_code)
        parser.parse_bytes('curve_data', 4)

        public_key = PublicKey.from_params(PublicKeyParamsEcdsa.from_octet_bit_string(
            parser['curve_identifier'].value.named_group,
            parser['curve_data'],
        ))

        del parser['curve_identifier']
        del parser['curve_data']

        return public_key

    def _compose_host_key_params(self, composer):
        named_group = self.public_key.params.named_group
        for elliptic_curve_identifier in SshEllipticCurveIdentifier:
            if elliptic_curve_identifier.value.named_group == named_group:
                composer.compose_string(elliptic_curve_identifier.value.code, 'ascii', 4)
                break
        else:
            raise NotImplementedError(named_group)

        composer.compose_bytes(self.public_key.params.octet_bit_string, 4)


@attr.s
class SshHostKeyECDSA(SshHostKeyECDSABase, SshHostKeyParserBase):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s
class SshHostKeyEDDSABase(SshHostKeyBase):
    @property
    @abc.abstractmethod
    def key_bytes(self):
        raise NotImplementedError()

    @classmethod
    def get_host_key_algorithms(cls):
        return filter(
            lambda host_key_algorithm: (
                host_key_algorithm.value.key_type == SshHostKeyType.HOST_KEY and
                host_key_algorithm.value.signature.value.key_type == Authentication.EDDSA
            ),
            SshHostKeyAlgorithm
        )

    @classmethod
    def _parse_host_key(cls, parser):
        parser.parse_bytes('key_data', 4)

        public_key = PublicKey.from_params(PublicKeyParamsEddsa(
            curve_type=NamedGroup.CURVE25519,
            key_data=parser['key_data'],
        ))

        del parser['key_data']

        return public_key

    def _compose_host_key_params(self, composer):
        composer.compose_bytes(self.public_key.params.key_data, 4)


@attr.s
class SshHostKeyEDDSA(SshHostKeyEDDSABase, SshHostKeyParserBase):
    @property
    def key_bytes(self):
        return self.compose()


@attr.s(frozen=True)
class SshCertTypeParams(Serializable):
    code = attr.ib(validator=attr.validators.instance_of(int))
    name = attr.ib(validator=attr.validators.instance_of(str))

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

        parser.parse_string('signature_type', 4, 'ascii', SshHostKeyAlgorithm.from_code)
        parser.parse_bytes('signature_data', 4)

        return cls(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_string(self.signature_type.value.code, 'ascii', 4)
        composer.compose_bytes(self.signature_data, 4)

        return composer.composed


@attr.s
class SshString(ParsableBase):
    value = attr.ib(validator=attr.validators.instance_of(str))

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
class SshCertExtensionParam():
    code = attr.ib(validator=attr.validators.instance_of(str))
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
    extension_name = attr.ib(validator=attr.validators.instance_of(str))
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
        header_composer = super()._compose_header()

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
    command = attr.ib(validator=attr.validators.instance_of(str))

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


class SshCertificateBase():
    @classmethod
    @abc.abstractmethod
    def _parse_host_key_algorithm(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def _compose_host_key_algorithm(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse_host_key(cls, parser):
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
        validator=attr.validators.instance_of(str),
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
    def _parse_host_key(cls, parser):
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

        public_key = cls._parse_host_key(parser)

        cls._parse_host_cert_params(parser)

        return cls(public_key=public_key, **parser), parser.parsed_length

    def compose(self):
        composer = self._compose_host_key_algorithm()

        self._compose_host_key_params(composer)
        self._compose_host_cert_params(composer)

        return composer.composed


class SshHostCertificateBase():
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
    serial = attr.ib(validator=attr.validators.instance_of(int))
    certificate_type = attr.ib(validator=attr.validators.instance_of(SshCertType))
    key_id = attr.ib(validator=attr.validators.instance_of(str))
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
    def _parse_host_key(cls, parser):
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

        public_key = cls._parse_host_key(parser)

        cls._parse_host_cert_params(parser)

        return cls(public_key=public_key, **parser), parser.parsed_length

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
            SshHostKeyAlgorithm.ECDSA_SHA2_SECP256K1_OID_CERT_V01_OPENSSH_COM,
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


@attr.s
class SshX509Certificate(ParsableBase, SshHostKeyBase):
    _NOT_DEFINED_HOST_KEY_ALGORITHMS_BY_PUBLIC_KEY_TYPE = {
        Authentication.RSA: SshHostKeyAlgorithm.X509V3_SIGN_RSA,
        Authentication.DSS: SshHostKeyAlgorithm.X509V3_SIGN_DSS,
    }

    @classmethod
    def get_host_key_algorithms(cls):
        return filter(
            lambda host_key_algorithm: host_key_algorithm.value.key_type == SshHostKeyType.X509_CERTIFICATE,
            SshHostKeyAlgorithm
        )

    @property
    def key_bytes(self):
        return self.public_key.public_key.der

    @classmethod
    def _parse(cls, parsable):
        try:
            parser = cls._parse_host_key_algorithm(parsable)
        except (InvalidValue, NotEnoughData):
            parser = ParserBinary(parsable)
            host_key_algorithm = None
        else:
            host_key_algorithm = parser['host_key_algorithm']

        if host_key_algorithm is None:
            public_key_length = parser.unparsed_length
        else:
            parser.parse_numeric('public_key_length', 4)
            public_key_length = parser['public_key_length']

        try:
            parser.parse_raw('public_key', public_key_length, PublicKeyX509.from_der)
        except (NotEnoughData, InvalidValue) as e:
            raise InvalidValue(parser.unparsed, cls, 'public_key') from e

        public_key = parser['public_key']
        if host_key_algorithm is None:
            host_key_algorithm = cls._NOT_DEFINED_HOST_KEY_ALGORITHMS_BY_PUBLIC_KEY_TYPE.get(public_key.key_type, None)
            if host_key_algorithm is None:
                raise InvalidType()

        return cls(host_key_algorithm, public_key), parser.parsed_length

    def compose(self):
        public_key_bytes = self.public_key.der

        if self.host_key_algorithm in [SshHostKeyAlgorithm.X509V3_SIGN_RSA, SshHostKeyAlgorithm.X509V3_SIGN_DSS]:
            composer = ComposerBinary()
        else:
            composer = self._compose_host_key_algorithm()
            composer.compose_numeric(len(public_key_bytes), 4)

        composer.compose_raw(public_key_bytes)

        return composer.composed


@attr.s
class SshX509CertificateChain(ParsableBase, SshHostKeyBase):
    issuer_certificates = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(PublicKey))
    )
    ocsp_responses = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of((bytes, bytearray)))
    )

    @classmethod
    def get_host_key_algorithms(cls):
        return filter(
            lambda host_key_algorithm: host_key_algorithm.value.key_type == SshHostKeyType.X509_CERTIFICATE_CHAIN,
            SshHostKeyAlgorithm
        )

    @property
    def key_bytes(self):
        return self.public_key.key_bytes

    @classmethod
    def _parse(cls, parsable):
        parser = cls._parse_host_key_algorithm(parsable)

        parser.parse_numeric('certificate_count', 4)
        certificates = []
        for _ in range(parser['certificate_count']):
            parser.parse_bytes('certificate', 4)
            certificates.append(PublicKeyX509.from_der(bytes(parser['certificate'])))

        parser.parse_numeric('ocsp_response_count', 4)
        ocsp_responses = []
        for _ in range(parser['ocsp_response_count']):
            parser.parse_bytes('ocsp_response', 4)
            ocsp_responses.append(parser['ocsp_response'])

        return cls(
            parser['host_key_algorithm'],
            certificates[0], certificates[1:],
            ocsp_responses,
        ), parser.parsed_length

    def compose(self):
        composer = self._compose_host_key_algorithm()

        composer.compose_numeric(len(self.issuer_certificates) + 1, 4)
        for certificate in [self.public_key] + self.issuer_certificates:
            composer.compose_bytes(certificate.der, 4)

        composer.compose_numeric(len(self.ocsp_responses), 4)
        for ocsp_response in self.ocsp_responses:
            composer.compose_bytes(ocsp_response, 4)

        return composer.composed

    def _asdict(self):
        return collections.OrderedDict([
            ('key_type', self.host_key_algorithm.value.key_type.value),
            ('certificate_chain', [self.public_key] + self.issuer_certificates),
        ])


class SshHostPublicKeyVariant(VariantParsable):
    _VARIANTS = collections.OrderedDict(itertools.chain.from_iterable([
        [
            (host_key_algorithm, (ssh_key_class, ))
            for host_key_algorithm in ssh_key_class.get_host_key_algorithms()
        ]
        for ssh_key_class in [
            SshHostKeyDSS,
            SshHostKeyECDSA,
            SshHostKeyEDDSA,
            SshHostKeyRSA,
            SshHostCertificateV00DSS,
            SshHostCertificateV00RSA,
            SshHostCertificateV01DSS,
            SshHostCertificateV01ECDSA,
            SshHostCertificateV01EDDSA,
            SshHostCertificateV01RSA,
            SshX509Certificate,
            SshX509CertificateChain,
        ]
    ]))

    @classmethod
    def _get_variants(cls):
        return cls._VARIANTS
