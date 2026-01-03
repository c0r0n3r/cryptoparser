# -*- coding: utf-8 -*-

import collections
import unittest

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.ike.algorithm import (
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
    Ikev2TransformType,
)

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.ike.ikev2 import (
    Ikev2Proposal,
    Ikev2ProposalNextPayload,
    Ikev2PayloadSecurityAssociation,
    Ikev2PayloadFlags,
    Ikev2PayloadType,
    Ikev2TransformPrf,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    TransformAttributeSignatureAlgorithm,
    TransformNextPayload,
)

from .classes import TransformTest


class TestTransformAttributeSignatureAlgorithm(unittest.TestCase):
    def setUp(self):
        self.signature_algorithm = (
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f'
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'
        )

        self.signature_algorithm_payload = TransformAttributeSignatureAlgorithm(
            signature_algorithm=self.signature_algorithm
        )

        self.signature_algorithm_dict = collections.OrderedDict([
            ('format', b'\x00'),  # TYPE_LENGTH_VALUE
            ('type', b'\x12'),  # SIGNATURE_ALGORITHM = 18
            ('length', b'\x00\x20'),  # 32 bytes length
            ('signature_algorithm', self.signature_algorithm),
        ])
        self.signature_algorithm_bytes = b''.join(self.signature_algorithm_dict.values())

    def test_parse(self):
        parsed_signature_algorithm = TransformAttributeSignatureAlgorithm.parse_exact_size(
            self.signature_algorithm_bytes
        )
        self.assertEqual(parsed_signature_algorithm.signature_algorithm, self.signature_algorithm)

    def test_compose(self):
        composed_bytes = self.signature_algorithm_payload.compose()

        parsed_signature_algorithm = TransformAttributeSignatureAlgorithm.parse_exact_size(composed_bytes)
        self.assertEqual(
            parsed_signature_algorithm.signature_algorithm,
            self.signature_algorithm_payload.signature_algorithm
        )

    def test_round_trip(self):
        composed_bytes = self.signature_algorithm_payload.compose()
        parsed_payload: TransformAttributeSignatureAlgorithm = (
            TransformAttributeSignatureAlgorithm.parse_exact_size(composed_bytes)
        )

        self.assertEqual(parsed_payload.signature_algorithm, self.signature_algorithm_payload.signature_algorithm)

    def test_error_parse_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            TransformAttributeSignatureAlgorithm.parse_exact_size(b'\x00\x12')
        self.assertEqual(context_manager.exception.bytes_needed, 2)

        incomplete = self.signature_algorithm_bytes[:-1]
        with self.assertRaises(NotEnoughData) as context_manager:
            TransformAttributeSignatureAlgorithm.parse_exact_size(incomplete)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_error_invalid_type(self):
        wrong_type_header = b'\x00\x11\x00\x20'  # wrong type 0x11 instead of 0x12
        wrong_type_bytes = wrong_type_header + self.signature_algorithm
        with self.assertRaises(Exception):
            TransformAttributeSignatureAlgorithm.parse_exact_size(wrong_type_bytes)

    def test_error_invalid_signature_algorithm_type(self):
        with self.assertRaises(TypeError):
            TransformAttributeSignatureAlgorithm(
                signature_algorithm="not_bytes"
            )


class TestTransform(unittest.TestCase):
    def setUp(self):
        self.transform_id = Ikev2PseudorandomFunction.PRF_HMAC_SHA1

        self.transform = TransformTest(
            transform_id=self.transform_id
        )
        self.transform.next_payload = TransformNextPayload.LAST

        self.transform_dict = collections.OrderedDict([
            ('next_payload', b'\x00'),  # LAST
            ('reserved1', b'\x00'),
            ('transform_length', b'\x00\x08'),  # 8 bytes header only
            ('transform_type', b'\x02'),  # PRF
            ('reserved2', b'\x00'),
            ('transform_id', b'\x00\x02'),  # PRF_HMAC_SHA1
        ])
        self.transform_bytes = b''.join(self.transform_dict.values())

    def test_parse(self):
        parsed_transform = TransformTest.parse_exact_size(self.transform_bytes)
        self.assertEqual(parsed_transform.transform_id, self.transform_id)
        self.assertEqual(parsed_transform.next_payload, TransformNextPayload.LAST)

    def test_compose(self):
        composed_bytes = self.transform.compose()
        self.assertEqual(len(composed_bytes), 8)  # Header only, no attributes

        parsed_transform = TransformTest.parse_exact_size(composed_bytes)
        self.assertEqual(parsed_transform.transform_id, self.transform.transform_id)

    def test_round_trip(self):
        composed_bytes = self.transform.compose()
        parsed_payload: TransformTest = TransformTest.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_payload.transform_id, self.transform.transform_id)
        self.assertEqual(parsed_payload.next_payload, self.transform.next_payload)

    def test_get_transform_type(self):
        self.assertEqual(TransformTest.get_transform_type(), Ikev2TransformType.PRF)

    def test_get_transform_id_class(self):
        self.assertEqual(
            TransformTest._get_transform_id_class(),  # pylint: disable=protected-access
            Ikev2PseudorandomFunction
        )

    def test_error_parse_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            TransformTest.parse_exact_size(b'\x00\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, 5)

        incomplete = self.transform_bytes[:-1]
        with self.assertRaises(NotEnoughData) as context_manager:
            TransformTest.parse_exact_size(incomplete)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_error_invalid_transform_id(self):
        with self.assertRaises(InvalidValue):
            TransformTest(
                transform_id="invalid_id"
            )


class TestIkev2TransformPrf(unittest.TestCase):
    def test_get_transform_type(self):
        self.assertEqual(Ikev2TransformPrf.get_transform_type(), Ikev2TransformType.PRF)

    def test_get_transform_id_class(self):
        self.assertEqual(
            Ikev2TransformPrf._get_transform_id_class(),  # pylint: disable=protected-access
            Ikev2PseudorandomFunction
        )


class TestIkev2TransformDhGroup(unittest.TestCase):
    def test_get_transform_type(self):
        self.assertEqual(Ikev2TransformDhGroup.get_transform_type(), Ikev2TransformType.DH)

    def test_get_transform_id_class(self):
        self.assertEqual(
            Ikev2TransformDhGroup._get_transform_id_class(),  # pylint: disable=protected-access
            Ikev2DiffieHellmanGroup
        )


class TestIkev2TransformIntegrity(unittest.TestCase):
    def test_get_transform_type(self):
        self.assertEqual(Ikev2TransformIntegrity.get_transform_type(), Ikev2TransformType.INTEG)

    def test_get_transform_id_class(self):
        self.assertEqual(
            Ikev2TransformIntegrity._get_transform_id_class(),  # pylint: disable=protected-access
            Ikev2IntegrityAlgorithm
        )


class TestIkev2TransformEncryptionAlgorithm(unittest.TestCase):
    def setUp(self):
        self.encryption_algorithm = Ikev2EncryptionAlgorithm.ENCR_AES_CBC
        self.key_length = 128
        self.transform = Ikev2TransformEncryptionAlgorithm(
            transform_id=self.encryption_algorithm,
            key_length=self.key_length
        )
        self.transform.next_payload = TransformNextPayload.LAST

    def test_get_transform_type(self):
        self.assertEqual(Ikev2TransformEncryptionAlgorithm.get_transform_type(), Ikev2TransformType.ENCR)

    def test_get_transform_id_class(self):
        self.assertEqual(
            Ikev2TransformEncryptionAlgorithm._get_transform_id_class(),  # pylint: disable=protected-access
            Ikev2EncryptionAlgorithm
        )

    def test_key_length_value_support(self):
        different_key_lengths = [128, 192, 256]

        for key_length in different_key_lengths:
            transform = Ikev2TransformEncryptionAlgorithm(
                transform_id=self.encryption_algorithm,
                key_length=key_length
            )
            self.assertEqual(transform.key_length, key_length)

    def test_parse(self):
        composed_bytes = self.transform.compose()
        parsed_transform = Ikev2TransformEncryptionAlgorithm.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_transform.transform_id, self.transform.transform_id)
        self.assertEqual(parsed_transform.key_length, self.transform.key_length)  # pylint: disable=no-member

    def test_compose(self):
        composed_bytes = self.transform.compose()
        self.assertGreater(len(composed_bytes), 8)

    def test_round_trip(self):
        composed_bytes = self.transform.compose()
        parsed_transform = Ikev2TransformEncryptionAlgorithm.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_transform.transform_id, self.transform.transform_id)
        self.assertEqual(parsed_transform.key_length, self.transform.key_length)  # pylint: disable=no-member

    def test_error_parse_not_enough_data(self):
        incomplete_data = b'\x00\x00\x00\x08\x01\x00\x00\x0c'

        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2TransformEncryptionAlgorithm.parse_exact_size(incomplete_data)
        self.assertGreater(context_manager.exception.bytes_needed, 0)


class TestIkev2Proposal(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.transform_prf = Ikev2TransformPrf(
            transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1
        )
        self.transform_prf.next_payload = TransformNextPayload.LAST

        self.protocol_id = Ikev2ProtocolId.IKE
        self.spi = b'\x00\x01\x02\x03'

        self.proposal_minimal = Ikev2Proposal(
            protocol_id=self.protocol_id,
            transforms=[self.transform_prf],
            spi=bytes()
        )
        self.proposal_minimal.last = Ikev2ProposalNextPayload.LAST
        self.proposal_minimal.proposal_number = 1

        self.proposal_with_spi = Ikev2Proposal(
            protocol_id=self.protocol_id,
            transforms=[self.transform_prf],
            spi=self.spi
        )
        self.proposal_with_spi.last = Ikev2ProposalNextPayload.MORE
        self.proposal_with_spi.proposal_number = 2

        self.proposal_dict_minimal = collections.OrderedDict([
            ('last', b'\x00'),  # LAST
            ('reserved', b'\x00'),
            ('proposal_length', b'\x00\x10'),  # 16 bytes total (8 header + 8 transform)
            ('proposal_number', b'\x01'),  # 1
            ('protocol_id', b'\x01'),  # IKE
            ('spi_size', b'\x00'),  # 0 bytes
            ('transform_count', b'\x01'),  # 1 transform
            # No SPI data
            # Transform data: next_payload(1) + reserved(1) + length(2) + type(1) + reserved(1) + id(2)
            ('transform_data', b'\x00\x00\x00\x08\x02\x00\x00\x02'),  # PRF_HMAC_SHA1
        ])
        self.proposal_bytes_minimal = b''.join(self.proposal_dict_minimal.values())
        self.proposal_minimal = Ikev2Proposal(
            protocol_id=self.protocol_id,
            transforms=[self.transform_prf],
            spi=bytes()
        )
        self.proposal_minimal.last = Ikev2ProposalNextPayload.LAST
        self.proposal_minimal.proposal_number = 1

        self.proposal_dict_with_spi = collections.OrderedDict([
            ('last', b'\x02'),  # MORE enum value
            ('reserved', b'\x00'),
            ('proposal_length', b'\x00\x10'),  # 16 bytes total (8 header + 8 transform)
            ('proposal_number', b'\x02'),  # 2
            ('protocol_id', b'\x01'),  # IKE
            ('spi_size', b'\x04'),  # 4 bytes
            ('transform_count', b'\x01'),  # 1 transform
            ('spi', self.spi),  # SPI data
            ('transform_data', b'\x00\x00\x00\x08\x02\x00\x00\x02'),  # PRF_HMAC_SHA1
        ])
        self.proposal_bytes_with_spi = b''.join(self.proposal_dict_with_spi.values())
        self.proposal_with_spi = Ikev2Proposal(
            protocol_id=self.protocol_id,
            transforms=[self.transform_prf],
            spi=self.spi
        )
        self.proposal_with_spi.last = Ikev2ProposalNextPayload.MORE
        self.proposal_with_spi.proposal_number = 2

    def test_parse(self):
        parsed_proposal = Ikev2Proposal.parse_exact_size(self.proposal_bytes_minimal)
        self.assertEqual(parsed_proposal.protocol_id, self.protocol_id)
        self.assertEqual(parsed_proposal.spi, bytes())
        self.assertEqual(len(parsed_proposal.transforms), 1)
        self.assertEqual(parsed_proposal.last, set())
        self.assertEqual(parsed_proposal.proposal_number, 1)

        parsed_proposal_spi = Ikev2Proposal.parse_exact_size(self.proposal_bytes_with_spi)
        self.assertEqual(parsed_proposal_spi.protocol_id, self.protocol_id)
        self.assertEqual(parsed_proposal_spi.spi, self.spi)
        self.assertEqual(len(parsed_proposal_spi.transforms), 1)
        self.assertEqual(parsed_proposal_spi.last, {Ikev2ProposalNextPayload.MORE})
        self.assertEqual(parsed_proposal_spi.proposal_number, 2)

    def test_compose(self):
        composed_bytes = self.proposal_minimal.compose()
        self.assertEqual(composed_bytes, self.proposal_bytes_minimal)

        composed_bytes = self.proposal_with_spi.compose()
        self.assertEqual(composed_bytes, self.proposal_bytes_with_spi)

    def test_round_trip(self):
        composed_bytes = self.proposal_minimal.compose()
        parsed_proposal: Ikev2Proposal = Ikev2Proposal.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_proposal.protocol_id, self.proposal_minimal.protocol_id)
        self.assertEqual(parsed_proposal.spi, self.proposal_minimal.spi)
        self.assertEqual(len(parsed_proposal.transforms), len(self.proposal_minimal.transforms))
        self.assertEqual(parsed_proposal.last, set())
        self.assertEqual(parsed_proposal.proposal_number, self.proposal_minimal.proposal_number)

    def test_error_parse_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2Proposal.parse_exact_size(b'\x00\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, Ikev2Proposal.HEADER_SIZE - 3)

        incomplete = self.proposal_bytes_minimal[:-1]
        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2Proposal.parse_exact_size(incomplete)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_error_invalid_protocol_id(self):
        with self.assertRaises(TypeError):
            Ikev2Proposal(
                protocol_id="invalid_protocol",
                transforms=[self.transform_prf]
            )

    def test_error_invalid_transforms(self):
        with self.assertRaises(TypeError):
            Ikev2Proposal(
                protocol_id=self.protocol_id,
                transforms=["invalid_transform"]
            )

    def test_error_invalid_spi_type(self):
        with self.assertRaises(TypeError):
            Ikev2Proposal(
                protocol_id=self.protocol_id,
                transforms=[self.transform_prf],
                spi="invalid_spi"
            )


class TestIkev2PayloadSecurityAssociation(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.transform_prf = Ikev2TransformPrf(
            transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1
        )
        self.transform_prf.next_payload = TransformNextPayload.LAST

        self.proposal_single = Ikev2Proposal(
            protocol_id=Ikev2ProtocolId.IKE,
            transforms=[self.transform_prf],
            spi=bytes()
        )

        self.proposal_with_spi = Ikev2Proposal(
            protocol_id=Ikev2ProtocolId.IKE,
            transforms=[self.transform_prf],
            spi=b'\x00\x01\x02\x03'
        )

        self.sa_single_proposal = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[self.proposal_single]
        )
        self.sa_single_proposal.next_payload = Ikev2PayloadType.NONE

        self.sa_multiple_proposals = Ikev2PayloadSecurityAssociation(
            flags={Ikev2PayloadFlags.CRITICAL},
            proposals=[self.proposal_single, self.proposal_with_spi]
        )
        self.sa_multiple_proposals.next_payload = Ikev2PayloadType.KE

        # Single proposal: header(4) + proposal(16) = 20 bytes total
        self.sa_dict_single = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE
            ('flags', b'\x00'),  # No flags
            ('payload_length', b'\x00\x14'),  # 20 bytes total
            ('proposals_data', b'\x00\x00\x00\x10\x01\x01\x00\x01\x00\x00\x00\x08\x02\x00\x00\x02'),
        ])
        self.sa_bytes_single = b''.join(self.sa_dict_single.values())

        # Multiple proposals: header(4) + proposal1(16) + proposal2(20) = 40 bytes total
        self.sa_dict_multiple = collections.OrderedDict([
            ('next_payload', b'\x22'),  # KE
            ('flags', b'\x80'),  # CRITICAL
            ('payload_length', b'\x00\x28'),  # 40 bytes total
            ('proposals_data', (
                b'\x02\x00\x00\x10\x01\x01\x00\x01\x00\x00\x00\x08\x02\x00\x00\x02' +  # proposal 1
                b'\x00\x00\x00\x10\x02\x01\x04\x01\x00\x01\x02\x03\x00\x00\x00\x08\x02\x00\x00\x02'  # proposal 2
            )),
        ])
        self.sa_bytes_multiple = b''.join(self.sa_dict_multiple.values())

    def test_parse(self):
        parsed_sa = Ikev2PayloadSecurityAssociation.parse_exact_size(self.sa_bytes_single)
        self.assertEqual(parsed_sa.next_payload, Ikev2PayloadType.NONE)
        self.assertEqual(parsed_sa.flags, set())
        self.assertEqual(len(parsed_sa.proposals), 1)
        self.assertEqual(parsed_sa.proposals[0].protocol_id, Ikev2ProtocolId.IKE)

        parsed_sa_multiple = Ikev2PayloadSecurityAssociation.parse_exact_size(self.sa_bytes_multiple)
        self.assertEqual(parsed_sa_multiple.next_payload, Ikev2PayloadType.KE)
        self.assertEqual(parsed_sa_multiple.flags, {Ikev2PayloadFlags.CRITICAL})
        self.assertEqual(len(parsed_sa_multiple.proposals), 2)

    def test_compose(self):
        composed_bytes = self.sa_single_proposal.compose()
        self.assertEqual(composed_bytes, self.sa_bytes_single)

        composed_bytes_multiple = self.sa_multiple_proposals.compose()
        self.assertEqual(composed_bytes_multiple, self.sa_bytes_multiple)

    def test_round_trip(self):
        composed_bytes = self.sa_single_proposal.compose()
        parsed_sa: Ikev2PayloadSecurityAssociation = Ikev2PayloadSecurityAssociation.parse_exact_size(composed_bytes)

        self.assertEqual(parsed_sa.next_payload, self.sa_single_proposal.next_payload)
        self.assertEqual(parsed_sa.flags, self.sa_single_proposal.flags)
        self.assertEqual(len(parsed_sa.proposals), len(self.sa_single_proposal.proposals))

    def test_get_payload_type(self):
        self.assertEqual(Ikev2PayloadSecurityAssociation.get_payload_type(), Ikev2PayloadType.SA)

    def test_error_parse_not_enough_data(self):
        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadSecurityAssociation.parse_exact_size(b'\x00\x01\x02')
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        incomplete = self.sa_bytes_single[:-1]
        with self.assertRaises(NotEnoughData) as context_manager:
            Ikev2PayloadSecurityAssociation.parse_exact_size(incomplete)
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_error_invalid_proposals(self):
        with self.assertRaises(TypeError):
            Ikev2PayloadSecurityAssociation(
                flags=set(),
                proposals=["invalid_proposal"]
            )

    def test_get_transform_by_type(self):
        transform_prf = Ikev2TransformPrf(
            transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1
        )
        transform_prf.next_payload = TransformNextPayload.LAST

        transform_dh = Ikev2TransformDhGroup(
            transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT
        )
        transform_dh.next_payload = TransformNextPayload.LAST

        transform_encr = Ikev2TransformEncryptionAlgorithm(
            transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            key_length=128
        )
        transform_encr.next_payload = TransformNextPayload.LAST

        proposal = Ikev2Proposal(
            protocol_id=Ikev2ProtocolId.IKE,
            transforms=[transform_prf, transform_dh, transform_encr],
            spi=bytes()
        )

        sa_payload = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[proposal]
        )

        found_prf = sa_payload.get_transform_by_type(Ikev2TransformType.PRF)
        self.assertEqual(found_prf, transform_prf)
        self.assertEqual(found_prf.get_transform_type(), Ikev2TransformType.PRF)

        found_dh = sa_payload.get_transform_by_type(Ikev2TransformType.DH)
        self.assertEqual(found_dh, transform_dh)
        self.assertEqual(found_dh.get_transform_type(), Ikev2TransformType.DH)

        found_encr = sa_payload.get_transform_by_type(Ikev2TransformType.ENCR)
        self.assertEqual(found_encr, transform_encr)
        self.assertEqual(found_encr.get_transform_type(), Ikev2TransformType.ENCR)

        transform_integ = Ikev2TransformIntegrity(
            transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96
        )
        transform_integ.next_payload = TransformNextPayload.LAST

        proposal_with_integ = Ikev2Proposal(
            protocol_id=Ikev2ProtocolId.IKE,
            transforms=[transform_integ],
            spi=bytes()
        )

        sa_payload_with_integ = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[proposal_with_integ]
        )

        found_integ = sa_payload_with_integ.get_transform_by_type(Ikev2TransformType.INTEG)
        self.assertEqual(found_integ, transform_integ)
        self.assertEqual(found_integ.get_transform_type(), Ikev2TransformType.INTEG)

    def test_get_transform_by_type_multiple_proposals(self):
        transform_prf1 = Ikev2TransformPrf(
            transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1
        )
        transform_prf1.next_payload = TransformNextPayload.LAST

        transform_prf2 = Ikev2TransformPrf(
            transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256
        )
        transform_prf2.next_payload = TransformNextPayload.LAST

        proposal1 = Ikev2Proposal(
            protocol_id=Ikev2ProtocolId.IKE,
            transforms=[transform_prf1],
            spi=bytes()
        )

        proposal2 = Ikev2Proposal(
            protocol_id=Ikev2ProtocolId.IKE,
            transforms=[transform_prf2],
            spi=bytes()
        )

        sa_payload = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[proposal1, proposal2]
        )

        found_prf = sa_payload.get_transform_by_type(Ikev2TransformType.PRF)
        self.assertEqual(found_prf.get_transform_type(), Ikev2TransformType.PRF)
        self.assertIn(found_prf, [transform_prf1, transform_prf2])

    def test_get_transform_by_type_not_found(self):
        sa_payload = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[self.proposal_single]
        )

        with self.assertRaises(KeyError) as context_manager:
            sa_payload.get_transform_by_type(Ikev2TransformType.DH)
        self.assertEqual(context_manager.exception.args[0], Ikev2TransformType.DH)

    def test_get_transform_by_type_empty_proposals(self):
        sa_payload = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[]
        )

        with self.assertRaises(KeyError) as context_manager:
            sa_payload.get_transform_by_type(Ikev2TransformType.PRF)
        self.assertEqual(context_manager.exception.args[0], Ikev2TransformType.PRF)


if __name__ == '__main__':
    unittest.main()
