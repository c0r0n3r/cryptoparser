# -*- coding: utf-8 -*-

import abc
import enum
import json
import math

try:
    from collections.abc import MutableSequence  # only works on python 3.3+
except ImportError:  # pragma: no cover
    from collections import MutableSequence

from collections import OrderedDict

from cryptoparser.common.parse import ParsableBase, ParserBinary, ComposerBinary
from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue


def _get_dict_result(dict_value):
    return OrderedDict([
        (name, _default(None, dict_value[name]))
        for name in sorted(dict_value.keys())
        if not name.startswith('_')
    ])


def _default(
        self,  # pylint: disable=unused-argument
        obj
):
    if isinstance(obj, enum.Enum) and hasattr(obj.value, '_asdict'):
        result = {obj.name: obj.value._asdict()}
    elif hasattr(obj, '_asdict'):
        result = obj._asdict()
    elif hasattr(obj, '__dict__'):
        result = _get_dict_result(obj.__dict__)
    elif isinstance(obj, dict):
        result = _get_dict_result(obj)
    elif isinstance(obj, (list, tuple)):
        result = [_default(None, item) for item in obj]
    elif isinstance(obj, (str, bool, int, float)) or obj is None:
        result = obj
    else:
        result = repr(obj)

    return result


_default.default = json.JSONEncoder().default
json.JSONEncoder.default = _default


class Serializable(object):  # pylint: disable=too-few-public-methods
    def _asdict(self):
        return _get_dict_result(self.__dict__)

    def as_json(self):
        return json.dumps(self._asdict())


class VectorParamBase(object):  # pylint: disable=too-few-public-methods
    def __init__(self, min_byte_num, max_byte_num):
        self.min_byte_num = min_byte_num
        self.max_byte_num = max_byte_num

        self.item_num_size = int(math.log(self.max_byte_num, 2) / 8) + 1

    @abc.abstractmethod
    def get_item_size(self, item):
        raise NotImplementedError()


class VectorParamNumeric(VectorParamBase):  # pylint: disable=too-few-public-methods
    def __init__(self, item_size, min_byte_num, max_byte_num, numeric_class=int):
        super(VectorParamNumeric, self).__init__(min_byte_num, max_byte_num)

        self.item_size = item_size
        self.numeric_class = numeric_class

    def get_item_size(self, item):
        return self.item_size


class VectorParamParsable(VectorParamBase):  # pylint: disable=too-few-public-methods
    def __init__(self, item_class, min_byte_num, max_byte_num, fallback_class):
        super(VectorParamParsable, self).__init__(min_byte_num, max_byte_num)

        self.item_class = item_class
        self.fallback_class = fallback_class

    def get_item_size(self, item):
        return len(item.compose())


class VectorBase(ParsableBase, MutableSequence):
    def __init__(self, items):
        super(VectorBase, self).__init__()

        self.param = self.get_param()

        self._items_size = 0
        self._items = []

        for item in items:
            self._items.append(item)
            self._items_size += self.param.get_item_size(item)

        self._update_items_size(del_item=None, insert_item=None)

    def _update_items_size(self, del_item=None, insert_item=None):
        size_diff = 0

        if del_item is not None:
            size_diff -= self.param.get_item_size(del_item)
        if insert_item is not None:
            size_diff += self.param.get_item_size(insert_item)

        if self._items_size + size_diff < self.param.min_byte_num:
            raise NotEnoughData(self.param.min_byte_num)
        if self._items_size + size_diff > self.param.max_byte_num:
            raise TooMuchData(self.param.max_byte_num)

        self._items_size += size_diff

    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    def __repr__(self):
        return "<{0} {1}>".format(self.__class__.__name__, self._items)

    def __len__(self):
        return len(self._items)

    def __getitem__(self, index):
        return self._items[index]

    def __delitem__(self, index):
        self._update_items_size(del_item=self._items[index])

        del self._items[index]

    def __setitem__(self, index, value):
        self._update_items_size(del_item=self._items[index], insert_item=value)
        self._items[index] = value

    def __str__(self):
        return str(self._items)

    def __eq__(self, other):
        return self._items == other._items  # pylint: disable=protected-access

    def insert(self, index, value):
        self._update_items_size(insert_item=value)

        self._items.insert(index, value)

    def append(self, value):
        self.insert(len(self._items), value)


class Vector(VectorBase):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        vector_param = cls.get_param()
        parser = ParserBinary(parsable)

        parser.parse_numeric('item_byte_num', vector_param.item_num_size)

        item_byte_num = parser['item_byte_num']
        item_num = int(item_byte_num / vector_param.item_size)
        parser.parse_numeric_array('items', item_num, vector_param.item_size, vector_param.numeric_class)

        return cls(parser['items']), parser.parsed_length

    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(len(self._items) * self.param.item_size, self.param.item_num_size)
        composer.compose_numeric_array(self._items, self.param.item_size)

        return composer.composed_bytes


class VectorParsable(VectorBase):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        vector_param = cls.get_param()

        parser = ParserBinary(parsable)

        parser.parse_numeric('item_byte_num', vector_param.item_num_size)
        try:
            parser.parse_parsable_array(
                'items',
                items_size=parser['item_byte_num'],
                item_class=vector_param.item_class
            )
        except NotEnoughData as e:
            raise NotEnoughData(e.bytes_needed)

        return cls(parser['items']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_parsable_array(self._items)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(body_composer.composed_length, self.param.item_num_size)

        return header_composer.composed_bytes + body_composer.composed_bytes


class VectorParsableDerived(VectorBase):
    @classmethod
    @abc.abstractmethod
    def get_param(cls):
        raise NotImplementedError()

    @classmethod
    def _parse(cls, parsable):
        vector_param = cls.get_param()

        parser = ParserBinary(parsable)

        parser.parse_numeric('item_byte_num', vector_param.item_num_size)
        parser.parse_parsable_derived_array(
            'items',
            items_size=parser['item_byte_num'],
            item_base_class=vector_param.item_class,
            fallback_class=vector_param.fallback_class
        )

        return cls(parser['items']), parser.parsed_length

    def compose(self):
        body_composer = ComposerBinary()
        body_composer.compose_parsable_array(self._items)

        header_composer = ComposerBinary()
        header_composer.compose_numeric(len(body_composer.composed_bytes), self.param.item_num_size)

        return header_composer.composed_bytes + body_composer.composed_bytes


class Opaque(Vector):
    @classmethod
    def _parse(cls, parsable):
        composer = ComposerBinary()
        vector_param = cls.get_param()
        composer.compose_numeric(vector_param.min_byte_num, vector_param.item_num_size)

        try:
            vector, parsed_length = super(Opaque, cls)._parse(composer.composed_bytes + parsable)
        except NotEnoughData:
            raise NotEnoughData(cls.get_byte_num())

        return cls(vector), parsed_length - vector_param.item_num_size

    def compose(self):
        return super(Opaque, self).compose()[self.param.item_num_size:]

    @classmethod
    @abc.abstractmethod
    def get_byte_num(cls):
        raise NotImplementedError()

    @classmethod
    def get_param(cls):
        byte_num = cls.get_byte_num()
        return VectorParamNumeric(item_size=1, min_byte_num=byte_num, max_byte_num=byte_num)


class NByteEnumParsable(ParsableBase):
    @classmethod
    def _parse(cls, parsable):
        parser = ParserBinary(parsable)

        parser.parse_numeric('code', cls.get_byte_num())

        for enum_item in cls.get_enum_class():
            if enum_item.value.code == parser['code']:
                return enum_item, cls.get_byte_num()

        raise InvalidValue(parser['code'], cls, 'code')

    @classmethod
    @abc.abstractmethod
    def get_byte_num(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class TwoByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 2

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class ThreeByteEnumParsable(NByteEnumParsable):
    @classmethod
    def get_byte_num(cls):
        return 3

    @classmethod
    @abc.abstractmethod
    def get_enum_class(cls):
        raise NotImplementedError()


class NByteEnumComposer(object):
    def compose(self):
        composer = ComposerBinary()

        composer.compose_numeric(
            self.value.code,  # pylint: disable=no-member
            self.get_byte_num()
        )

        return composer.composed_bytes

    @classmethod
    @abc.abstractmethod
    def get_byte_num(cls):
        raise NotImplementedError()


class TwoByteEnumComposer(NByteEnumComposer):
    @classmethod
    def get_byte_num(cls):
        return 2


class ThreeByteEnumComposer(NByteEnumComposer):
    @classmethod
    def get_byte_num(cls):
        return 3
