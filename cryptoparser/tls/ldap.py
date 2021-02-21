# -*- coding: utf-8 -*-

import abc
import enum
import re
import six

import attr

import asn1crypto.core

from cryptoparser.common.exception import NotEnoughData, InvalidValue
from cryptoparser.common.parse import ParsableBase


class LDAPClass(enum.IntEnum):
    UNIVERSAL = 0
    APPLICATION = 1
    CONTEXT = 2


class LDAPResultCode(enum.IntEnum):
    SUCCESS = 0
    OPERATIONS_ERROR = 1
    PROTOCOL_ERROR = 2
    TIME_LIMIT_EXCEEDED = 3
    SIZE_LIMIT_EXCEEDED = 4
    COMPARE_FALSE = 5
    COMPARE_TRUE = 6
    AUTH_METHOD_NOT_SUPPORTED = 7
    STRONGER_AUTH_REQUIRED = 8
    REFERRAL = 10
    ADMIN_LIMIT_EXCEEDED = 11
    UNAVAILABLE_CRITICAL_EXTENSION = 12
    CONFIDENTIALITY_REQUIRED = 13
    SASL_BIND_IN_PROGRESS = 14
    NO_SUCH_ATTRIBUTE = 16
    UNDEFINED_ATTRIBUTE_TYPE = 17
    INAPPROPRIATE_MATCHING = 18
    CONSTRAINT_VIOLATION = 19
    ATTRIBUTE_OR_VALUE_EXISTS = 20
    INVALID_ATTRIBUTE_SYNTAX = 21
    NO_SUCH_OBJECT = 32
    ALIAS_PROBLEM = 33
    INVALID_DN_SYNTAX = 34
    ALIAS_DEREFERENCING_PROBLEM = 36
    INAPPROPRIATE_AUTHENTICATION = 48
    INVALID_CREDENTIALS = 49
    INSUFFICIENT_ACCESS_RIGHTS = 50
    BUSY = 51
    UNAVAILABLE = 52
    UNWILLING_TO_PERFORM = 53
    LOOP_DETECT = 54
    NAMING_VIOLATION = 64
    OBJECT_CLASS_VIOLATION = 65
    NOT_ALLOWED_ON_NON_LEAF = 66
    NOT_ALLOWED_ON_RDN = 67
    ENTRY_ALREADY_EXISTS = 68
    OBJECT_CLASS_MODS_PROHIBITED = 69
    AFFECTS_MULTIPLE_DSAS = 71
    OTHER = 80


class LDAPResultCodeEnum(asn1crypto.core.Enumerated):
    _map = {result_code.value: result_code for result_code in list(LDAPResultCode)}


class LDAPOID(asn1crypto.core.OctetString):
    pass


class LDAPControl(asn1crypto.core.Sequence):
    _fields = [
        ('controlType', LDAPOID),
        ('criticality', asn1crypto.core.Boolean, {'default': False}),
        ('controlValue', asn1crypto.core.OctetString, {'optional': True}),
    ]


class LDAPControls(asn1crypto.core.SequenceOf):
    _child_spec = LDAPControl


class LDAPExtendedRequest(asn1crypto.core.Sequence):
    _fields = [
        ('requestName', LDAPOID, {'implicit': (LDAPClass.CONTEXT.value, 0)}),
        ('requestValue', asn1crypto.core.OctetString, {'implicit': (LDAPClass.CONTEXT.value, 1), 'optional': True}),
    ]


class LDAPDN(asn1crypto.core.OctetString):
    pass


class LDAPString(asn1crypto.core.OctetString):
    pass


class LDAPURI(LDAPString):
    pass


class LDAPReferral(asn1crypto.core.SequenceOf):
    _child_spec = LDAPURI


class LDAPExtendedResponse(asn1crypto.core.Sequence):
    _fields = [
        ('resultCode', LDAPResultCodeEnum),
        ('matchedDN', LDAPDN),
        ('diagnosticMessage', LDAPString),
        ('referral', LDAPReferral,  {'implicit': (LDAPClass.CONTEXT.value, 3), 'optional': True}),
        ('responseName', LDAPOID, {'implicit': (LDAPClass.CONTEXT.value, 10), 'optional': True}),
        ('responseValue', asn1crypto.core.OctetString, {'implicit': (LDAPClass.CONTEXT.value, 11), 'optional': True}),
    ]


class LDAPProtocolOp(asn1crypto.core.Choice):
    _alternatives = [
        ('extendedReq', LDAPExtendedRequest, {'implicit': (LDAPClass.APPLICATION.value, 23)}),
        ('extendedResp', LDAPExtendedResponse, {'implicit': (LDAPClass.APPLICATION.value, 24)}),
    ]


class LDAPMessage(asn1crypto.core.Sequence):
    _fields = [
        ('messageID', asn1crypto.core.Integer),
        ('protocolOp', LDAPProtocolOp),
        ('controls', LDAPControls, {'implicit': (LDAPClass.CONTEXT.value, 0), 'optional': True}),
    ]


class LDAPMessageParsableBase(ParsableBase):
    HEADER_SIZE = 6

    _NOT_ENOUGH_DATA_REGEX = re.compile(
        r'Insufficient data - ([0-9]+) bytes requested but only ([0-9]+) available'
    )

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    def _parse_asn1(cls, parsable):
        try:
            message = LDAPMessage.load(bytes(parsable))
            # ensure recursive parsing
            message.native  # pylint: disable=pointless-statement
        except ValueError as e:
            match = cls._NOT_ENOUGH_DATA_REGEX.match(e.args[0])
            if match:
                bytes_requested = int(match.group(1))
                bytes_available = int(match.group(2))
                six.raise_from(NotEnoughData(bytes_requested - bytes_available), e)
            else:
                six.raise_from(InvalidValue(parsable, cls), e)

        return message


class LDAPExtendedRequestStartTLS(LDAPMessageParsableBase):
    @classmethod
    def _parse(cls, parsable):
        asn1_message = cls._parse_asn1(parsable)

        return LDAPExtendedRequestStartTLS(), len(asn1_message.dump())

    def compose(self):
        return LDAPMessage({
            'messageID': 1,
            'protocolOp': {
                'extendedReq': {
                    'requestName': b'1.3.6.1.4.1.1466.20037'
                }
            }
        }).dump()


@attr.s
class LDAPExtendedResponseStartTLS(LDAPMessageParsableBase):
    result_code = attr.ib(validator=attr.validators.in_(LDAPResultCode))

    @classmethod
    def _parse(cls, parsable):
        asn1_message = cls._parse_asn1(parsable)

        return LDAPExtendedResponseStartTLS(
            asn1_message['protocolOp'].chosen['resultCode'].native
        ), len(asn1_message.dump())

    def compose(self):
        return LDAPMessage({
            'messageID': 1,
            'protocolOp': {
                'extendedResp': {
                    'resultCode': self.result_code.value,
                    'matchedDN': b'',
                    'diagnosticMessage': b''
                }
            }
        }).dump()
