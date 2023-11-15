# -*- coding: utf-8 -*-
# pylint: disable=too-many-lines

import abc
import collections
import datetime
import enum
import json

import attr
import six
import urllib3

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.types import Base64Data, convert_base64_data, convert_value_to_object, convert_url

from cryptoparser.common.base import Serializable
from cryptoparser.common.exception import InvalidType, NotEnoughData
from cryptoparser.common.parse import ParserText, ParsableBase, ParsableBaseNoABC, ComposerText


class FieldParsableBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_separator(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_name(cls, parsable):
        separator = cls.get_separator()
        parser = ParserText(parsable)

        parser.parse_string_until_separator_or_end('name', separator)

        return parser

    @classmethod
    def _compose_name(cls, name):
        composer = ComposerText()

        composer.compose_string(name)

        return composer


@attr.s
class NameValueVariantBase(FieldParsableBase):
    value = attr.ib()

    @value.validator
    def _x_validator(self, attribute, value):  # pylint: disable=unused-argument
        value_class = self._get_value_class()
        if not isinstance(value, value_class):
            self.value = value_class(value)

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_class(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_separator(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_name_and_separator(cls, parsable):
        separator = cls.get_separator()
        parser = cls._parse_name(parsable)

        parser.parse_separator(separator)

        if parser['name'].lower() != cls.get_canonical_name().lower():
            raise InvalidType()

        return parser


@attr.s
class NameValuePair(FieldParsableBase):
    name = attr.ib(validator=attr.validators.instance_of(six.string_types))
    value = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)), default=None)
    quoted = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bool)), default=False)

    @classmethod
    def get_separator(cls):
        return '='

    @classmethod
    def _parse(cls, parsable):
        value = None
        quoted = False

        parser = cls._parse_name(parsable)
        if parser.unparsed_length:
            parser.parse_separator(cls.get_separator())
            parser.parse_string_by_length('value', min_length=0)
            value = parser['value']
            if value and value[0] == '"':
                quoted = True
                value = value[1:]
                if value and value[-1:] == '"':
                    value = value[:-1]

        return cls(parser['name'], value, quoted), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.name)
        if self.value is not None:
            composer.compose_separator(self.get_separator())
            if self.quoted:
                composer.compose_separator('"')
            composer.compose_string(self.value)
            if self.quoted:
                composer.compose_separator('"')

        return composer.composed


@attr.s
class NameValuePairList(ParsableBase, Serializable):
    value = attr.ib(
        default=collections.OrderedDict([]),
        validator=attr.validators.instance_of(collections.OrderedDict),
    )

    @classmethod
    @abc.abstractmethod
    def get_separator(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_array(
            'value',
            cls.get_separator(),
            item_class=NameValuePair,
            separator_spaces=' \t',
            skip_empty=True
        )

        return cls(
            collections.OrderedDict([(component.name, component.value) for component in parser['value']])
        ), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        separator = self.get_separator() + ' '
        for item_number, (name, value) in enumerate(self.value.items()):
            composer.compose_string(name)
            if value is not None:
                composer.compose_separator('=')
                composer.compose_string(value)

            if item_number + 1 < len(self.value):
                composer.compose_separator(separator)

        return composer.composed

    def _as_markdown(self, level):
        return self._markdown_result(self.value, level)


class NameValuePairListCommaSeparated(NameValuePairList):
    @classmethod
    def get_separator(cls):
        return ','


class NameValuePairListSemicolonSeparated(NameValuePairList):
    @classmethod
    def get_separator(cls):
        return ';'


def is_validator_optional(validator):
    return isinstance(validator, attr.validators._OptionalValidator)  # pylint: disable=protected-access


@attr.s
class FieldValueComponentBase(ParsableBase, Serializable):
    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
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
class FieldValueComponentOption(FieldValueComponentBase):
    value = attr.ib(validator=attr.validators.instance_of(bool))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)

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

    def _as_markdown(self, level):
        return self._markdown_result(self.value, level)


@attr.s
class FieldValueComponentKeyValueBase(FieldValueComponentBase):
    value = attr.ib()

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _parse_value(cls, parser):
        raise NotImplementedError()

    def _get_value_as_simple_type(self):
        # neccessary only because PY2 handles multiple inheritance differently than PY3
        if isinstance(self.value, ParsableBaseNoABC):
            return self.value.compose().decode('ascii')

        return self.value

    def _get_value_as_str(self):
        return str(self._get_value_as_simple_type())

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        name = cls.get_canonical_name()
        try:
            parser.parse_string_by_length('name', len(name), len(name))
        except NotEnoughData as e:
            six.raise_from(InvalidType, e)

        cls._check_name(parser['name'])

        if cls.get_canonical_name():
            parser.parse_separator('=')
        cls._parse_value(parser)
        parsed_value = parser['value']
        if cls.get_canonical_name():
            parsed_value = cls(parsed_value)

        return parsed_value, parser.parsed_length

    def compose(self):
        composer = ComposerText()

        if self.get_canonical_name():
            composer.compose_string_array([self.get_canonical_name(), self._get_value_as_str()], '=')
        else:
            composer.compose_string(self._get_value_as_str())

        return composer.composed

    def _as_markdown(self, level):
        return self._markdown_result(self.value, level)


@attr.s
class FieldValueComponentParsableBase(FieldValueComponentKeyValueBase):
    value = attr.ib()

    def __attrs_post_init__(self):
        value_class = self._get_value_class()
        if not isinstance(self.value, value_class):
            self.value = value_class(self.value)

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_class(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_parsable('value', cls._get_value_class())


class FieldValueComponentParsable(FieldValueComponentParsableBase):
    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_class(cls):
        raise NotImplementedError()


class FieldValueComponentParsableOptional(FieldValueComponentParsableBase):
    def __attrs_post_init__(self):
        if self.value is not None:
            super(FieldValueComponentParsableOptional, self).__attrs_post_init__()

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_class(cls):
        raise NotImplementedError()


@attr.s
class FieldValueComponentQuotedString(FieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    def _get_value_as_str(self):
        return '"{}"'.format(self.value)

    def _get_value_as_simple_type(self):
        return self.value

    @classmethod
    def _parse_value(cls, parser):

        parser.parse_separator('"', 0, None)
        parser.parse_string_until_separator_or_end('value', '"')
        parser.parse_separator('"', 0, None)


@attr.s
class FieldValueComponentDateTime(FieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.instance_of(datetime.datetime))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_date_time('value')

    def _get_value_as_simple_type(self):
        return self.value.strftime('%a, %d %b %Y %H:%M:%S GMT')


@attr.s
class FieldValueComponentTimeDelta(FieldValueComponentKeyValueBase):
    value = attr.ib(
        converter=convert_value_to_object(datetime.timedelta),
        validator=attr.validators.instance_of(datetime.timedelta)
    )

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def convert(cls, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, datetime.timedelta):
            return cls(value)

        return cls(datetime.timedelta(seconds=value))

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_time_delta('value')

    def _get_value_as_simple_type(self):
        return int(self.value.total_seconds())

    def _as_markdown(self, level):
        return self._markdown_result(str(self.value), level)


@attr.s
class FieldValueComponentStringBase64(FieldValueComponentQuotedString):
    value = attr.ib(
        converter=convert_base64_data(),
        validator=attr.validators.instance_of(Base64Data)
    )

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _check_name(cls, name):
        cls._check_name_insensitive(name)

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_string_by_length('value')


@attr.s
class FieldValueComponentBool(FieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.instance_of(bool))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    def _get_value_as_str(self):
        return 'yes' if self.value else 'no'

    def _get_value_as_simple_type(self):
        return self.value

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_bool('value')


@attr.s
class FieldValueComponentNumber(FieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.instance_of(int))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_numeric('value')


@attr.s
class FieldValueComponentFloat(FieldValueComponentNumber):
    value = attr.ib(
        converter=float,
        validator=attr.validators.instance_of(float)
    )

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    def _get_value_as_simple_type(self):
        return self.value

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_float('value')


@attr.s
class FieldValueComponentPercent(FieldValueComponentNumber):
    def __attrs_post_init__(self):
        if self.value < 0 or self.value > 100:
            raise InvalidValue(self.value, type(self), 'value')

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()


@attr.s
class FieldValueComponentStringEnumParams(object):
    code = attr.ib(validator=attr.validators.instance_of(six.string_types))


@attr.s
class FieldValueComponentStringEnum(FieldValueComponentKeyValueBase):
    value = attr.ib()

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_type(cls):
        raise NotImplementedError()

    @value.validator
    def _validator_value(self, _, value):
        if not isinstance(value, self._get_value_type()):
            raise InvalidValue(value, type(self), 'value')

    @classmethod
    def _parse_value(cls, parser):
        try:
            parser.parse_parsable('value', cls._get_value_type())
        except InvalidValue as e:
            six.raise_from(InvalidValue(e.value.decode('ascii'), cls, 'value'), e)

    def _get_value_as_simple_type(self):
        return self.value.value.code


@attr.s
class FieldValueComponentStringEnumOption(FieldValueComponentStringEnum):
    @classmethod
    @abc.abstractmethod
    def _get_value_type(cls):
        raise NotImplementedError()

    @classmethod
    def get_canonical_name(cls):
        return ''

    @classmethod
    def _check_name(cls, name):
        pass


@attr.s
class FieldValueComponentString(FieldValueComponentKeyValueBase):
    value = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_string_by_length('value')


@attr.s
class FieldValueComponentUrl(FieldValueComponentKeyValueBase):
    value = attr.ib()

    @value.validator
    def _value_validate(self, _, value):
        self.value = convert_url()(value)

        if isinstance(self.value, urllib3.util.Url):
            return

        raise InvalidValue(self.value, type(self), 'value')

    @classmethod
    @abc.abstractmethod
    def get_canonical_name(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_value(cls, parser):
        parser.parse_string_by_length('value', item_class=convert_url())

    def _get_value_as_simple_type(self):
        if self.value.scheme == 'mailto':
            value = 'mailto:' + self.value.path[1:]
        else:
            value = str(self.value)

        return value

    def _as_markdown(self, level):
        return self._markdown_result(self._get_value_as_simple_type(), level)


class FieldValueBase(ParsableBase, Serializable):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    def _get_attr_to_validator_type_dict(cls, attr_fields_dict):
        attr_to_component_name_dict = []

        for attribute in attr_fields_dict.values():
            validator = attribute.validator
            if is_validator_optional(validator):
                validator = validator.validator

            attr_to_component_name_dict.append((attribute.name, validator.type))

        return collections.OrderedDict(attr_to_component_name_dict)


class FieldsJson(FieldValueBase):
    @classmethod
    def _parse(cls, parsable):
        try:
            raw_values = json.loads(parsable.decode('ascii'), object_pairs_hook=collections.OrderedDict)
        except ValueError as e:  # json.decoder.JSONDecodeError is derived from ValueError
            six.raise_from(InvalidValue(six.ensure_text(parsable, 'ascii'), cls, 'value'), e)

        attr_fields_dict = attr.fields_dict(cls)

        return cls(**{
            attribute_name: raw_values[validator_class.get_canonical_name()]
            for attribute_name, validator_class in cls._get_attr_to_validator_type_dict(attr_fields_dict).items()
            if validator_class.get_canonical_name() in raw_values
        }), len(parsable)

    def compose(self):
        attr_fields_dict = attr.fields_dict(type(self))

        return json.dumps(collections.OrderedDict([
            (
                validator_class.get_canonical_name(),
                getattr(self, attribute_name)._get_value_as_simple_type()  # pylint: disable=protected-access
            )
            for attribute_name, validator_class in self._get_attr_to_validator_type_dict(attr_fields_dict).items()
            if getattr(self, attribute_name) is not None
        ])).encode('ascii')


class FieldValueMultiple(FieldValueBase):
    @classmethod
    @abc.abstractmethod
    def _get_header_value_list_class(cls):
        raise NotImplementedError()

    @classmethod
    def _parse_basic_params(cls, attr_to_component_name_dict, attr_fields_dict, components, params):
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

                component = attribute.default

            if attr_to_component_name_dict[name].get_canonical_name() in components:
                parsable = components.pop(attr_to_component_name_dict[name].get_canonical_name())
                if parsable is None:  # value is None in case of optional values
                    parsable = component
                else:
                    parsable = '='.join([attr_to_component_name_dict[name].get_canonical_name(), parsable])
                params[name] = attr_to_component_name_dict[name].parse_exact_size(six.ensure_binary(parsable, 'ascii'))
            else:
                params[name] = attribute.default

    @classmethod
    def _parse_extensions(cls, attr_to_component_name_dict, extension, components, params):
        if extension and components:
            name, _ = extension
            params[name] = attr_to_component_name_dict[name](components)

    @classmethod
    def _parse(cls, parsable):
        params = {}
        extension = None
        attr_fields_dict_basic = {}
        attr_fields_dict = attr.fields_dict(cls)
        for name, attribute in attr_fields_dict.items():
            if not attribute.metadata.get('extension', False):
                attr_fields_dict_basic[name] = attribute
            elif extension is None:
                extension = (name, attribute)
            else:
                raise NotImplementedError()
        attr_to_component_name_dict = cls._get_attr_to_validator_type_dict(attr_fields_dict)

        components = cls._get_header_value_list_class().parse_exact_size(parsable).value

        cls._parse_basic_params(attr_to_component_name_dict, attr_fields_dict_basic, components, params)
        cls._parse_extensions(attr_to_component_name_dict, extension, components, params)

        return cls(**params), len(parsable)

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
            if issubclass(validator.type, FieldValueComponentOption):
                if value is False:
                    continue

            components.append(getattr(self, name))

        separator = self._get_header_value_list_class().get_separator() + ' '
        composer.compose_string_array(components, separator)

        return composer.composed


class FieldsCommaSeparated(FieldValueMultiple):
    @classmethod
    def _get_header_value_list_class(cls):
        return NameValuePairListCommaSeparated


class FieldsSemicolonSeparated(FieldValueMultiple):
    @classmethod
    def _get_header_value_list_class(cls):
        return NameValuePairListSemicolonSeparated


class MimeTypeRegistry(enum.Enum):
    APPLICATION = 'application'
    AUDIO = 'audio'
    FONT = 'font'
    EXAMPLE = 'example'
    IMAGE = 'image'
    MESSAGE = 'message'
    MODEL = 'model'
    MULTIPART = 'multipart'
    TEXT = 'text'
    VIDEO = 'video'


@attr.s
class FieldValueMimeType(FieldValueComponentBase):
    type = attr.ib(
        validator=attr.validators.instance_of(six.string_types),
        default=None,
    )
    registry = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(MimeTypeRegistry)),
        default=None,
    )

    def __str__(self):
        return '{}/{}'.format(self.registry.value, self.type)

    @property
    def value(self):
        return self

    @classmethod
    def get_canonical_name(cls):
        return ''

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator('registry', '/', item_class=MimeTypeRegistry)
        parser.parse_separator('/')
        parser.parse_string_by_length('type', parser.unparsed_length)

        return FieldValueMimeType(**parser), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(str(self))

        return composer.composed

    @classmethod
    def _check_name(cls, name):
        pass


@attr.s
class FieldValueSingleBase(FieldValueBase, Serializable):
    value = attr.ib()

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_value_type(cls):
        raise NotImplementedError()

    @classmethod
    def convert(cls, value):
        if not isinstance(value, cls._get_value_type()):
            return value

        return cls(value)

    @value.validator
    def _value_validate(self, _, value):
        value_type = self._get_value_type()
        if not isinstance(value, value_type):
            raise InvalidValue(value, value_type, 'value')

    def _as_markdown(self, level):
        return self._markdown_result(self.value, level)


class FieldValueSingleSimpleBase(FieldValueSingleBase):
    @classmethod
    @abc.abstractmethod
    def _value_from_str(cls, value):
        raise NotImplementedError()


class FieldValueSingle(FieldValueSingleSimpleBase):
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


@attr.s
class FieldValueStringEnumParams(Serializable):
    code = attr.ib(validator=attr.validators.instance_of(six.string_types))
    human_readable_name = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types))
    )

    def _as_markdown(self, level):
        if self.human_readable_name:
            return self._markdown_result(self.human_readable_name, level)

        return False, self.code.replace('_', ' ')


class FieldValueString(FieldValueSingle):
    @classmethod
    def _get_value_type(cls):
        return six.string_types

    @classmethod
    def _value_from_str(cls, value):
        return str(value)


class FieldValueSingleComplexBase(FieldValueSingleBase):
    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


class FieldValueDateTime(FieldValueSingleComplexBase):
    @classmethod
    def _get_value_type(cls):
        return datetime.datetime

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_date_time('value')

        return cls(parser['value']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_date_time(self.value, '%a, %d %b %Y %H:%M:%S GMT')

        return composer.composed

    def _as_markdown(self, level):
        return self._markdown_result(self.value, level)


class FieldValueStringBySeparatorBase(FieldValueSingleComplexBase):
    @classmethod
    @abc.abstractmethod
    def _get_separators(cls):
        raise NotImplementedError()

    @classmethod
    def _get_value_type(cls):
        return six.string_types

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_string_until_separator_or_end('value', cls._get_separators())

        return cls(parser['value']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.value)

        return composer.composed


class FieldValueStringEnum(FieldValueSingleComplexBase):
    @classmethod
    @abc.abstractmethod
    def _get_value_type(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        try:
            value = cls._get_value_type().parse_exact_size(parsable)
        except InvalidValue as e:
            six.raise_from(InvalidValue(six.ensure_text(parsable, 'ascii'), cls, 'value'), e)

        return cls(value), len(parsable)

    def compose(self):
        composer = ComposerText()

        composer.compose_string(self.value.value.code)

        return composer.composed


class FieldValueTimeDelta(FieldValueSingleComplexBase):
    @classmethod
    def _get_value_type(cls):
        return datetime.timedelta

    @classmethod
    def _parse(cls, parsable):
        parser = ParserText(parsable)

        parser.parse_time_delta('value')

        return cls(parser['value']), parser.parsed_length

    def compose(self):
        composer = ComposerText()

        composer.compose_time_delta(self.value)

        return composer.composed
