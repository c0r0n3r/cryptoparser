#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.tls.subprotocol import TlsSubprotocolMessageBase, TlsHandshakeMessage, TlsHandshakeType


class TestMessage(TlsSubprotocolMessageBase):
    @classmethod
    def get_handshake_type(cls):
        raise NotImplementedError


class TestVariantMessage(TlsHandshakeMessage):
    @classmethod
    def get_handshake_type(cls):
        return TlsHandshakeType.SERVER_HELLO_DONE

    @classmethod
    def _parse(cls, parsable):
        raise NotImplementedError

    def compose(self):
        raise NotImplementedError
