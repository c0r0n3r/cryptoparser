# -*- coding: utf-8 -*-

import abc
import enum
import struct
import attr

import six

from cryptoparser.common.exception import NotEnoughData, TooMuchData, InvalidValue
import cryptoparser.common.utils


@six.add_metaclass(abc.ABCMeta)
class ParsableBase(object):
    @classmethod
    def parse_mutable(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        del parsable[:parsed_length]
        return parsed_object

    @classmethod
    def parse_immutable(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        return parsed_object, parsed_length

    @classmethod
    def parse_exact_size(cls, parsable):
        parsed_object, parsed_length = cls._parse(parsable)
        if len(parsable) > parsed_length:
            raise TooMuchData(parsed_length)

        return parsed_object

    @classmethod
    @abc.abstractmethod
    def _parse(cls, parsable):
        raise NotImplementedError()

    @abc.abstractmethod
    def compose(self):
        raise NotImplementedError()


_SIZE_TO_FORMAT = {
    1: 'B',
    2: 'H',
    3: 'I',
    4: 'I',
}


class ByteOrder(enum.Enum):
    NATIVE = '='
    LITTLE_ENDIAN = '<'
    BIG_ENDIAN = '>'
    NETWORK = '!'


@attr.s
class ParserBinary(object):
    _parsable = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))
    byte_order = attr.ib(default=ByteOrder.NETWORK, validator=attr.validators.in_(ByteOrder))
    _parsed_length = attr.ib(init=False, default=0)
    _parsed_values = attr.ib(init=False, default=dict())

    def __getitem__(self, key):
        return self._parsed_values[key]

    @property
    def parsed_length(self):
        return self._parsed_length

    @property
    def unparsed(self):
        return self._parsable[self._parsed_length:]

    @property
    def unparsed_length(self):
        return len(self._parsable) - self._parsed_length

    def _parse_numeric_array(self, name, item_num, item_size, item_numeric_class):
        if self._parsed_length + (item_num * item_size) > len(self._parsable):
            raise NotEnoughData(bytes_needed=(item_num * item_size) - self.unparsed_length)

        if item_size in _SIZE_TO_FORMAT:
            value = list()
            for item_offset in range(self._parsed_length, self._parsed_length + (item_num * item_size), item_size):
                item_bytes = self._parsable[item_offset:item_offset + item_size]
                if item_size == 3:
                    item_bytes = b'\x00' + item_bytes

                item = struct.unpack(
                    self.byte_order.value + _SIZE_TO_FORMAT[item_size],
                    item_bytes
                )[0]
                try:
                    value.append(item_numeric_class(item))
                except ValueError as e:
                    six.raise_from(InvalidValue(item, item_numeric_class), e)
        else:
            raise NotImplementedError()

        self._parsed_length += item_num * item_size
        self._parsed_values[name] = value

    def parse_numeric(self, name, size, numeric_class=int):
        self._parse_numeric_array(name, 1, size, numeric_class)
        self._parsed_values[name] = self._parsed_values[name][0]

    def parse_numeric_array(self, name, item_num, item_size, numeric_class=int):
        self._parse_numeric_array(name, item_num, item_size, numeric_class)

    def parse_numeric_flags(self, name, size, flags_class):
        self._parse_numeric_array(name, 1, size, int)
        self._parsed_values[name] = [
            flags_class(flag & self._parsed_values[name][0])
            for flag in flags_class
            if flag & self._parsed_values[name][0]
        ]

    def parse_bytes(self, name, size):
        if self.unparsed_length < size:
            raise NotEnoughData(bytes_needed=size - self.unparsed_length)

        self._parsed_values[name] = self._parsable[self._parsed_length: self._parsed_length + size]
        self._parsed_length += size

    def parse_parsable(self, name, parsable_class):
        parsed_object, parsed_length = parsable_class.parse_immutable(
            self._parsable[self._parsed_length:]
        )
        self._parsed_length += parsed_length
        self._parsed_values[name] = parsed_object

    def _parse_parsable_array(self, name, items_size, item_classes, fallback_class=None):
        if items_size > self.unparsed_length:
            raise NotEnoughData(bytes_needed=items_size - self.unparsed_length)

        items = []
        unparsed_bytes = self._parsable[self._parsed_length:self._parsed_length + items_size]

        while unparsed_bytes:
            for item_class in item_classes:
                try:
                    item, parsed_length = item_class.parse_immutable(unparsed_bytes)
                    break
                except InvalidValue:
                    pass
            else:
                if fallback_class is not None:
                    item, parsed_length = fallback_class.parse_immutable(unparsed_bytes)
                else:
                    raise ValueError(unparsed_bytes)

            unparsed_bytes = unparsed_bytes[parsed_length:]
            items.append(item)

        self._parsed_values[name] = items
        self._parsed_length += items_size

    def parse_parsable_array(self, name, items_size, item_class, fallback_class=None):
        try:
            return self._parse_parsable_array(name, items_size, [item_class, ], fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            six.raise_from(InvalidValue(e.args[0], item_class, name), e)

    def parse_parsable_derived_array(self, name, items_size, item_base_class, fallback_class=None):
        item_classes = cryptoparser.common.utils.get_leaf_classes(item_base_class)
        try:
            return self._parse_parsable_array(name, items_size, item_classes, fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            six.raise_from(InvalidValue(e.args[0], item_base_class), e)

    def parse_variant(self, name, variant):
        parsed_object, value_length = variant.parse(self._parsable[self._parsed_length:])

        self._parsed_values[name] = parsed_object
        self._parsed_length += value_length


@attr.s
class ComposerBinary(object):
    _composed = attr.ib(init=False, default=bytes())
    byte_order = attr.ib(default=ByteOrder.NETWORK, validator=attr.validators.in_(ByteOrder))

    def _compose_numeric_array(self, values, item_size):
        composed_bytes = bytearray()

        for value in values:
            try:
                composed_bytes += struct.pack(
                    self.byte_order.value + _SIZE_TO_FORMAT[item_size],
                    value
                )

                if item_size == 3:
                    del composed_bytes[-4]

            except struct.error as e:
                six.raise_from(InvalidValue(value, int), e)

        self._composed += composed_bytes

    def compose_numeric(self, value, size):
        self._compose_numeric_array([value, ], size)

    def compose_numeric_array(self, values, item_size):
        self._compose_numeric_array(values, item_size)

    def compose_numeric_flags(self, values, item_size):
        flag = 0
        for value in values:
            flag |= value
        self._compose_numeric_array([flag, ], item_size)

    def compose_parsable(self, value):
        self._composed += value.compose()

    def compose_parsable_array(self, values):
        composed_bytes = bytearray()

        for item in values:
            composed_bytes += item.compose()

        self._composed += composed_bytes

    def compose_bytes(self, value):
        self._composed += value

    @property
    def composed_bytes(self):
        return bytearray(self._composed)

    @property
    def composed_length(self):
        return len(self._composed)
