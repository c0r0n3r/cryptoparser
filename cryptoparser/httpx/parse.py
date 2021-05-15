#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import datetime

from collections import OrderedDict

import attr

import six

from cryptoparser.common.base import Serializable
from cryptoparser.common.exception import InvalidValue, InvalidType, NotEnoughData
from cryptoparser.common.parse import ParsableBase, ParserText, ComposerText


def is_validator_optional(validator):
    return isinstance(validator, attr.validators._OptionalValidator)  # pylint: disable=protected-access


@attr.s
class HttpHeaderFieldValueComponent(ParsableBase):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    value = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)), default=None)
    quoted = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bool)), default=False)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator_or_end('name', '=')

        value = None
        quoted = False

        if parser.unparsed_length:
            parser.parse_separator('=')
            parser.parse_string_by_length('value', min_length=0)
            value = parser['value']
            if value and value[0] == '"':
                quoted = True
                value = value[1:]
                if value and value[-1:] == '"':
                    value = value[:-1]

        return HttpHeaderFieldValueComponent(parser['name'], value, quoted), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.name)
        if self.value is not None:
            composer.compose_separator('=')
            if self.quoted:
                composer.compose_separator('"')
            composer.compose_string(self.value)
            if self.quoted:
                composer.compose_separator('"')

        return composer.composed


class HttpHeaderFieldValueBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


@attr.s
class HttpHeaderFieldValueSingle(HttpHeaderFieldValueBase, Serializable):
    value = attr.ib()

    @value.validator
    def _value_validate(self, _, value):
        value_type = self._get_value_type()
        if not isinstance(value, value_type):
            raise InvalidValue(value, value_type, 'value')

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_by_length('value')
        value = cls._value_from_str(parser['value'])

        return cls(value), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.value)

        return composer.composed

    @classmethod
    @abc.abstractmethod
    def _get_value_type(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _value_from_str(cls, value):
        raise NotImplementedError()

    def _value_to_str(self):
        return self.compose().decode('ascii')

    def _as_markdown(self, level):
        return self._markdown_result(self._value_to_str(), level)


@attr.s
class HttpHeaderFieldValueStringEnumParams(object):
    code = attr.ib(validator=attr.validators.instance_of(six.string_types))


class HttpHeaderFieldValueStringEnum(HttpHeaderFieldValueSingle):
    @classmethod
    @abc.abstractmethod
    def _get_value_type(cls):
        raise NotImplementedError()

    @classmethod
    def _value_from_str(cls, value):
        try:
            parsed_value = cls._get_value_type().parse_exact_size(value.encode('ascii'))
        except InvalidValue as e:
            six.raise_from(InvalidValue(value, cls, 'value'), e)

        return parsed_value


class HttpHeaderFieldValueString(HttpHeaderFieldValueSingle):
    @classmethod
    def _get_value_type(cls):
        return str

    @classmethod
    def _value_from_str(cls, value):
        return str(value)


@attr.s
class HttpHeaderFieldValueList(HttpHeaderFieldValueBase):
    components = attr.ib(validator=attr.validators.instance_of(OrderedDict), default=OrderedDict([]))

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_array(
            'components', ';', item_class=HttpHeaderFieldValueComponent, separator_spaces=' \t', skip_empty=True
        )

        return HttpHeaderFieldValueList(
            OrderedDict([(component.name, component.value) for component in parser['components']])
        ), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        for item_number, (name, value) in enumerate(self.components.items()):
            composer.compose_string(name)
            if value is not None:
                composer.compose_separator('=')
                composer.compose_string(value)

            if item_number + 1 < len(self.components):
                composer.compose_separator('; ')

        return composer.composed


class HttpHeaderFieldValueMultiple(HttpHeaderFieldValueBase):
    @classmethod
    def _from_field_values(cls, components):
        attr_fields_dict = attr.fields_dict(cls)
        attr_to_component_name_dict = {}

        for attribute in attr_fields_dict.values():
            validator = attribute.validator
            if is_validator_optional(validator):
                validator = validator.validator

            attr_to_component_name_dict[attribute.name] = validator.type

        params = {}
        for name, attribute in attr_fields_dict.items():
            for component in components:
                try:
                    attr_to_component_name_dict[name]._check_name(component)  # pylint: disable=protected-access
                except InvalidType:
                    pass
                else:
                    components[attr_to_component_name_dict[name].get_canonical_name()] = components.pop(component)
                    break
            else:
                if attribute.default == attr.NOTHING:
                    raise InvalidValue(None, cls, name)

            if attr_to_component_name_dict[name].get_canonical_name() in components:
                parsable = components[attr_to_component_name_dict[name].get_canonical_name()]
                if parsable is None:  # value is None in  case of optional values
                    parsable = attr_to_component_name_dict[name].get_canonical_name()
                else:
                    parsable = '='.join([attr_to_component_name_dict[name].get_canonical_name(), parsable])
                params[name] = attr_to_component_name_dict[name].parse_exact_size(parsable.encode('ascii'))
            else:
                params[name] = attribute.default

        return cls(**params)

    @classmethod
    def _parse(cls, parsable):
        header_field_value = HttpHeaderFieldValueList.parse_exact_size(parsable)
        return cls._from_field_values(header_field_value.components), len(parsable)

    def compose(self):
        composer = ComposerText()

        cls = type(self)
        attr_fields_dict = attr.fields_dict(cls)
        components = []
        for name, attribute in attr_fields_dict.items():
            field_value = getattr(self, name)
            validator = attribute.validator

            if is_validator_optional(validator):
                if field_value is None:
                    continue

                validator = validator.validator

            value = field_value.value
            if issubclass(validator.type, HttpHeaderFieldValueComponentOption):
                if value is False:
                    continue

            components.append(getattr(self, name))

        composer.compose_string_array(components, '; ')

        return composer.composed


@attr.s
class HttpHeaderFieldValueComponentBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    def compose(self):
        raise NotImplementedError()

    @classmethod
    def convert(cls, value):
        if not isinstance(value, cls):
            value = cls(value)

        return value

    @classmethod
    def _check_name_insensitive(cls, name):
        if name.lower() != cls.get_canonical_name().lower():
            raise InvalidType()

    @classmethod
    def _check_name(cls, name):
        if name != cls.get_canonical_name():
            raise InvalidType()


@attr.s
class HttpHeaderFieldValueComponentOption(HttpHeaderFieldValueComponentBase):
    value = attr.ib(validator=attr.validators.instance_of(bool))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        try:
            canonical_name = cls.get_canonical_name()
            parser.parse_string_by_length('value', len(canonical_name), len(canonical_name))
            cls._check_name(parser['value'])
            value = True
        except (InvalidValue, NotEnoughData):
            value = False

        return cls(value), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        if self.value:
            composer.compose_string(self.get_canonical_name())

        return composer.composed


@attr.s
class HttpHeaderFieldValueComponentKeyValueBase(HttpHeaderFieldValueComponentBase):
    value = attr.ib(validator=attr.validators.instance_of(bool))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse_value(cls, parser):
        raise NotImplementedError()

    def _get_value_as_str(self):
        return str(self.value)

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        name = cls.get_canonical_name()
        try:
            parser.parse_string_by_length('name', len(name), len(name))
        except NotEnoughData as e:
            six.raise_from(InvalidType, e)

        cls._check_name(parser['name'])

        parser.parse_separator('=')
        cls._parse_value(parser)

        return cls(parser['value']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string_array([self.get_canonical_name(), self._get_value_as_str()], '=')

        return composer.composed


@attr.s
class HttpHeaderFieldValueComponentString(HttpHeaderFieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_string_by_length('value')


@attr.s
class HttpHeaderFieldValueComponentQuotedString(HttpHeaderFieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    def _get_value_as_str(self):
        return '"{}"'.format(self.value)

    @classmethod
    def _parse_value(cls, parser):

        parser.parse_separator('"', 0, None)
        parser.parse_string_until_separator_or_end('value', '"')
        parser.parse_separator('"', 0, None)


@attr.s
class HttpHeaderFieldValueComponentNumber(HttpHeaderFieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.instance_of(int))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_numeric('value')


@attr.s
class HttpHeaderFieldValueComponentTimeDelta(HttpHeaderFieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.instance_of(datetime.timedelta))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_time_delta('value')

    def _get_value_as_str(self):
        return str(int(self.value.total_seconds()))


class HttpHeaderFieldValueComponentMaxAge(HttpHeaderFieldValueComponentTimeDelta):
    @classmethod
    def get_canonical_name(cls):
        return 'max-age'

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)


class HttpHeaderFieldValueComponentReportURI(HttpHeaderFieldValueComponentQuotedString):
    @classmethod
    def get_canonical_name(cls):
        return 'report-uri'

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)
