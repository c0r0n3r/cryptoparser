# -*- coding: utf-8 -*-

import abc
import struct

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
        unparsed_bytes = parsable[parsed_length:]
        return parsed_object, unparsed_bytes

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


class ParserBinary(object):
    _INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
    }

    def __init__(self, parsable):
        self._parsable = parsable
        self._parsed_length = 0
        self._parsed_values = dict()

    def __getitem__(self, key):
        return self._parsed_values[key]

    @property
    def parsed_length(self):
        return self._parsed_length

    @property
    def unparsed_length(self):
        return len(self._parsable) - self._parsed_length

    def _parse_numeric_array(self, name, item_num, item_size, item_numeric_class):
        if self._parsed_length + (item_num * item_size) > len(self._parsable):
            raise NotEnoughData(bytes_needed=(item_num * item_size) - self.unparsed_length)

        if item_size in self._INT_FORMATER_BY_SIZE:
            value = list()
            for item_offset in range(self._parsed_length, self._parsed_length + (item_num * item_size), item_size):
                item_bytes = self._parsable[item_offset:item_offset + item_size]
                if item_size == 3:
                    item_bytes = b'\x00' + item_bytes

                item = struct.unpack(
                    self._INT_FORMATER_BY_SIZE[item_size],
                    item_bytes
                )[0]
                try:
                    value.append(item_numeric_class(item))
                except ValueError:
                    raise InvalidValue(item, item_numeric_class)
        else:
            raise NotImplementedError()

        self._parsed_length += item_num * item_size
        self._parsed_values[name] = value

    def parse_numeric(self, name, size, numeric_class=int):
        self._parse_numeric_array(name, 1, size, numeric_class)
        self._parsed_values[name] = self._parsed_values[name][0]

    def parse_numeric_array(self, name, item_num, item_size, numeric_class=int):
        self._parse_numeric_array(name, item_num, item_size, numeric_class)

    def parse_bytes(self, name, size):
        if self.unparsed_length < size:
            raise NotEnoughData(bytes_needed=size - self.unparsed_length)

        self._parsed_values[name] = self._parsable[self._parsed_length: self._parsed_length + size]
        self._parsed_length += size

    def parse_parsable(self, name, parsable_class):
        parsed_object, unparsed_bytes = parsable_class.parse_immutable(
            self._parsable[self._parsed_length:]
        )
        self._parsed_length += len(self._parsable) - self._parsed_length - len(unparsed_bytes)
        self._parsed_values[name] = parsed_object

    def _parse_parsable_array(self, name, items_size, item_classes, fallback_class=None):
        if items_size > self.unparsed_length:
            raise NotEnoughData(bytes_needed=items_size - self.unparsed_length)

        items = []
        unparsed_bytes = self._parsable[self._parsed_length:self._parsed_length + items_size]

        while unparsed_bytes:
            for item_class in item_classes:
                try:
                    item, unparsed_bytes = item_class.parse_immutable(unparsed_bytes)
                    break
                except InvalidValue:
                    pass
            else:
                if fallback_class is not None:
                    item, unparsed_bytes = fallback_class.parse_immutable(unparsed_bytes)
                else:
                    raise ValueError(unparsed_bytes)

            items.append(item)

        self._parsed_values[name] = items
        self._parsed_length += items_size

    def parse_parsable_array(self, name, items_size, item_class):
        if self.unparsed_length < items_size:
            raise NotEnoughData(items_size)

        try:
            return self._parse_parsable_array(name, items_size, [item_class, ])
        except ValueError as e:
            raise InvalidValue(e.args[0], item_class, name)

    def parse_parsable_derived_array(self, name, items_size, item_base_class, fallback_class=None):
        item_classes = cryptoparser.common.utils.get_leaf_classes(item_base_class)
        try:
            return self._parse_parsable_array(name, items_size, item_classes, fallback_class)
        except NotEnoughData as e:
            raise e
        except ValueError as e:
            raise InvalidValue(e.args[0], item_base_class)

    def parse_variant(self, name, variant):
        parsed_object, value_length = variant.parse(self._parsable[self._parsed_length:])

        self._parsed_values[name] = parsed_object
        self._parsed_length += value_length


class ComposerBinary(object):
    _INT_FORMATER_BY_SIZE = {
        1: '!B',
        2: '!H',
        3: '!I',
        4: '!I',
    }

    def __init__(self):
        self._composed = bytearray()

    def _compose_numeric_array(self, values, item_size):
        composed_bytes = bytearray()

        for value in values:
            try:
                composed_bytes += struct.pack(
                    self._INT_FORMATER_BY_SIZE[item_size],
                    value
                )

                if item_size == 3:
                    del composed_bytes[-4]

            except struct.error:
                raise InvalidValue(value, int)

        self._composed += composed_bytes

    def compose_numeric(self, value, size):
        self._compose_numeric_array([value, ], size)

    def compose_numeric_array(self, values, item_size):
        self._compose_numeric_array(values, item_size)

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
