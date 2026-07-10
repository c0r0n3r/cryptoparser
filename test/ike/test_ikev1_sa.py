# SPDX-License-Identifier: MPL-2.0

import collections
import unittest

from cryptodatahub.ike.algorithm import (
    Ikev1PayloadType, Ikev1AuthenticationMethod, Ikev1TransformId, Ikev1ProtocolId, Ikev1Doi
)

from cryptoparser.ike.ikev1 import (
    Ikev1AttributeAuthenticationMethod, Ikev1PayloadTransform, Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation, Ikev1Situation
)


class TestIkev1PayloadProposal(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        self.simple_transform = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[]
        )

        self.auth_attribute = Ikev1AttributeAuthenticationMethod(value=Ikev1AuthenticationMethod.PRE_SHARED_KEY)
        self.transform_with_attr = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[self.auth_attribute]
        )

        self.test_dict_single_transform = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x10'),  # 16 bytes total
            ('proposal_number', b'\x01'),
            ('protocol_id', b'\x01'),  # ISAKMP = 0x01
            ('spi_size', b'\x00'),
            ('transform_count', b'\x01'),
            ('transform_data', b'\x00\x00\x00\x08\x01\x01\x00\x00'),  # 8-byte transform
        ])
        self.test_bytes_single_transform = b''.join(self.test_dict_single_transform.values())

        self.spi_data = b'\x12\x34\x56\x78'
        self.test_dict_with_spi = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x14'),  # 20 bytes total
            ('proposal_number', b'\x01'),
            ('protocol_id', b'\x03'),  # IPSEC_ESP = 0x03
            ('spi_size', b'\x04'),  # 4-byte SPI
            ('transform_count', b'\x01'),
            ('spi', self.spi_data),
            ('transform_data', b'\x00\x00\x00\x08\x01\x01\x00\x00'),  # 8-byte transform
        ])
        self.test_bytes_with_spi = b''.join(self.test_dict_with_spi.values())

        self.test_dict_multi_transforms = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x18'),  # 24 bytes total
            ('proposal_number', b'\x01'),
            ('protocol_id', b'\x01'),  # ISAKMP = 0x01
            ('spi_size', b'\x00'),
            ('transform_count', b'\x02'),
            ('transform1_data', b'\x03\x00\x00\x08\x01\x01\x00\x00'),  # next=TRANSFORM
            ('transform2_data', b'\x00\x00\x00\x08\x02\x01\x00\x00'),  # next=NONE
        ])
        self.test_bytes_multi_transforms = b''.join(self.test_dict_multi_transforms.values())

        self.proposal_single = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.ISAKMP,
            transforms=[self.simple_transform],
            spi=b''
        )
        self.proposal_single.proposal_number = 1
        self.proposal_single.next_payload = Ikev1PayloadType.NONE

        self.proposal_with_spi = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.IPSEC_ESP,
            transforms=[self.simple_transform],
            spi=self.spi_data
        )
        self.proposal_with_spi.proposal_number = 1
        self.proposal_with_spi.next_payload = Ikev1PayloadType.NONE

        self.second_transform = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[]
        )

        self.proposal_multi = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.ISAKMP,
            transforms=[self.simple_transform, self.second_transform],
            spi=b''
        )
        self.proposal_multi.proposal_number = 1
        self.proposal_multi.next_payload = Ikev1PayloadType.NONE

    def test_get_payload_type(self):
        self.assertEqual(Ikev1PayloadProposal.get_payload_type(), Ikev1PayloadType.PROPOSAL)

    def test_constructor_with_single_transform(self):
        proposal = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.ISAKMP,
            transforms=[self.simple_transform],
            spi=b''
        )
        self.assertEqual(proposal.protocol_id, Ikev1ProtocolId.ISAKMP)
        self.assertEqual(len(proposal.transforms), 1)
        self.assertEqual(proposal.transforms[0], self.simple_transform)
        self.assertEqual(proposal.spi, b'')

    def test_constructor_with_spi(self):
        proposal = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.IPSEC_ESP,
            transforms=[self.simple_transform],
            spi=self.spi_data
        )
        self.assertEqual(proposal.protocol_id, Ikev1ProtocolId.IPSEC_ESP)
        self.assertEqual(proposal.spi, self.spi_data)

    def test_constructor_with_multiple_transforms(self):
        proposal = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.ISAKMP,
            transforms=[self.simple_transform, self.second_transform],
            spi=b''
        )
        self.assertEqual(len(proposal.transforms), 2)
        self.assertEqual(proposal.transforms[0], self.simple_transform)
        self.assertEqual(proposal.transforms[1], self.second_transform)

    def test_parse_single_transform(self):
        parsed: Ikev1PayloadProposal = Ikev1PayloadProposal.parse_exact_size(self.test_bytes_single_transform)

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NONE)
        self.assertEqual(parsed.proposal_number, 1)
        self.assertEqual(parsed.protocol_id, Ikev1ProtocolId.ISAKMP)
        self.assertEqual(parsed.spi, b'')
        self.assertEqual(len(parsed.transforms), 1)
        self.assertEqual(parsed.transforms[0].transform_id, Ikev1TransformId.KEY_IKE)

    def test_parse_with_spi(self):
        parsed: Ikev1PayloadProposal = Ikev1PayloadProposal.parse_exact_size(self.test_bytes_with_spi)

        self.assertEqual(parsed.protocol_id, Ikev1ProtocolId.IPSEC_ESP)
        self.assertEqual(parsed.spi, self.spi_data)
        self.assertEqual(len(parsed.transforms), 1)

    def test_parse_multiple_transforms(self):
        parsed: Ikev1PayloadProposal = Ikev1PayloadProposal.parse_exact_size(self.test_bytes_multi_transforms)

        self.assertEqual(parsed.proposal_number, 1)
        self.assertEqual(parsed.protocol_id, Ikev1ProtocolId.ISAKMP)
        self.assertEqual(len(parsed.transforms), 2)
        self.assertEqual(parsed.transforms[0].transform_id, Ikev1TransformId.KEY_IKE)
        self.assertEqual(parsed.transforms[1].transform_id, Ikev1TransformId.KEY_IKE)

    def test_compose_single_transform(self):
        composed_bytes = self.proposal_single.compose()
        self.assertEqual(composed_bytes, self.test_bytes_single_transform)

    def test_compose_with_spi(self):
        composed_bytes = self.proposal_with_spi.compose()
        self.assertEqual(composed_bytes, self.test_bytes_with_spi)

    def test_compose_multiple_transforms(self):
        composed_bytes = self.proposal_multi.compose()
        self.assertEqual(composed_bytes, self.test_bytes_multi_transforms)

    def test_round_trip_single_transform(self):
        composed_bytes = self.proposal_single.compose()
        parsed: Ikev1PayloadProposal = Ikev1PayloadProposal.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.protocol_id, self.proposal_single.protocol_id)
        self.assertEqual(parsed.spi, self.proposal_single.spi)
        self.assertEqual(len(parsed.transforms), len(self.proposal_single.transforms))
        self.assertEqual(parsed.proposal_number, self.proposal_single.proposal_number)
        self.assertEqual(parsed.next_payload, self.proposal_single.next_payload)

    def test_round_trip_with_spi(self):
        composed_bytes = self.proposal_with_spi.compose()
        parsed: Ikev1PayloadProposal = Ikev1PayloadProposal.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.protocol_id, self.proposal_with_spi.protocol_id)
        self.assertEqual(parsed.spi, self.proposal_with_spi.spi)
        self.assertEqual(len(parsed.transforms), len(self.proposal_with_spi.transforms))

    def test_round_trip_multiple_transforms(self):
        composed_bytes = self.proposal_multi.compose()
        parsed: Ikev1PayloadProposal = Ikev1PayloadProposal.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.protocol_id, self.proposal_multi.protocol_id)
        self.assertEqual(len(parsed.transforms), len(self.proposal_multi.transforms))
        self.assertEqual(parsed.transforms[0].next_payload, Ikev1PayloadType.TRANSFORM)
        self.assertEqual(parsed.transforms[1].next_payload, Ikev1PayloadType.NONE)

    def test_transform_numbering_in_compose(self):
        composed_bytes = self.proposal_multi.compose()

        self.assertEqual(composed_bytes[12], 1)  # First transform number at byte 12
        self.assertEqual(composed_bytes[20], 2)  # Second transform number at byte 20

    def test_spi_size_calculation(self):
        different_spi = b'\xaa\xbb\xcc\xdd\xee\xff'  # 6 bytes
        proposal = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.IPSEC_AH,
            transforms=[self.simple_transform],
            spi=different_spi
        )
        proposal.proposal_number = 1
        proposal.next_payload = Ikev1PayloadType.NONE

        composed_bytes = proposal.compose()
        self.assertEqual(composed_bytes[6], 6)  # SPI size field at byte 6


class TestIkev1PayloadSecurityAssociation(unittest.TestCase):  # pylint: disable=too-many-instance-attributes
    def setUp(self):
        # Simple transform for proposals
        self.simple_transform = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[]
        )

        # Simple proposal for SA
        self.simple_proposal = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.ISAKMP,
            transforms=[self.simple_transform],
            spi=b''
        )

        # Second proposal for multi-proposal tests
        self.second_proposal = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.IPSEC_ESP,
            transforms=[self.simple_transform],
            spi=b'\x12\x34\x56\x78'
        )

        # Test data for SA with single proposal
        self.test_dict_single_proposal = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x1c'),  # 28 bytes total
            ('doi', b'\x00\x00\x00\x01'),  # IPSEC = 0x00000001
            ('situation', b'\x00\x00\x00\x01'),  # SIT_IDENTITY_ONLY = 0x00000001
            # Proposal: next=NONE, length=16, prop_num=1, protocol=ISAKMP, spi_size=0, transform_count=1
            ('proposal_data', b'\x00\x00\x00\x10\x01\x01\x00\x01'),
            # Transform: next=NONE, length=8, transform_num=1, transform_id=KEY_IKE
            ('transform_data', b'\x00\x00\x00\x08\x01\x01\x00\x00'),
        ])
        self.test_bytes_single_proposal = b''.join(self.test_dict_single_proposal.values())

        # Test data for SA with multiple proposals
        self.test_dict_multi_proposals = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x30'),  # 48 bytes total
            ('doi', b'\x00\x00\x00\x01'),  # IPSEC = 0x00000001
            ('situation', b'\x00\x00\x00\x01'),  # SIT_IDENTITY_ONLY = 0x00000001
            # First proposal: next=PROPOSAL, length=16, prop_num=1
            ('proposal1_data', b'\x02\x00\x00\x10\x01\x01\x00\x01'),
            ('transform1_data', b'\x00\x00\x00\x08\x01\x01\x00\x00'),
            # Second proposal: next=NONE, length=20, prop_num=2, protocol=ESP, 4-byte SPI
            ('proposal2_data', b'\x00\x00\x00\x14\x02\x03\x04\x01'),
            ('spi_data', b'\x12\x34\x56\x78'),
            ('transform2_data', b'\x00\x00\x00\x08\x01\x01\x00\x00'),
        ])
        self.test_bytes_multi_proposals = b''.join(self.test_dict_multi_proposals.values())

        # Test data for different situation flags
        self.test_dict_secrecy_integrity = collections.OrderedDict([
            ('next_payload', b'\x00'),  # NONE = 0x00
            ('reserved', b'\x00'),
            ('payload_length', b'\x00\x1c'),  # 28 bytes total
            ('doi', b'\x00\x00\x00\x01'),  # IPSEC = 0x00000001
            ('situation', b'\x00\x00\x00\x06'),  # SIT_SECRECY | SIT_INTEGRITY = 0x02 | 0x04 = 0x06
            ('proposal_data', b'\x00\x00\x00\x10\x01\x01\x00\x01'),
            ('transform_data', b'\x00\x00\x00\x08\x01\x01\x00\x00'),
        ])
        self.test_bytes_secrecy_integrity = b''.join(self.test_dict_secrecy_integrity.values())

        # SA objects for compose tests
        self.sa_single = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation={Ikev1Situation.SIT_IDENTITY_ONLY},
            proposals=[self.simple_proposal]
        )
        self.sa_single.next_payload = Ikev1PayloadType.NONE

        self.sa_multi = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation={Ikev1Situation.SIT_IDENTITY_ONLY},
            proposals=[self.simple_proposal, self.second_proposal]
        )
        self.sa_multi.next_payload = Ikev1PayloadType.NONE

        self.sa_flags = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation={Ikev1Situation.SIT_SECRECY, Ikev1Situation.SIT_INTEGRITY},
            proposals=[self.simple_proposal]
        )
        self.sa_flags.next_payload = Ikev1PayloadType.NONE

    def test_get_payload_type(self):
        self.assertEqual(Ikev1PayloadSecurityAssociation.get_payload_type(), Ikev1PayloadType.SECURITY_ASSOCIATION)

    def test_constructor_with_single_proposal(self):
        sa = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation={Ikev1Situation.SIT_IDENTITY_ONLY},
            proposals=[self.simple_proposal]
        )
        self.assertEqual(sa.doi, Ikev1Doi.IPSEC)
        self.assertEqual(sa.situation, {Ikev1Situation.SIT_IDENTITY_ONLY})
        self.assertEqual(len(sa.proposals), 1)
        self.assertEqual(sa.proposals[0], self.simple_proposal)

    def test_constructor_with_multiple_proposals(self):
        sa = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation={Ikev1Situation.SIT_IDENTITY_ONLY},
            proposals=[self.simple_proposal, self.second_proposal]
        )
        self.assertEqual(len(sa.proposals), 2)
        self.assertEqual(sa.proposals[0], self.simple_proposal)
        self.assertEqual(sa.proposals[1], self.second_proposal)

    def test_constructor_with_situation_flags(self):
        sa = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation={Ikev1Situation.SIT_SECRECY, Ikev1Situation.SIT_INTEGRITY},
            proposals=[self.simple_proposal]
        )
        self.assertEqual(sa.situation, {Ikev1Situation.SIT_SECRECY, Ikev1Situation.SIT_INTEGRITY})

    def test_doi_storage(self):
        sa = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.GDOI,
            situation={Ikev1Situation.SIT_IDENTITY_ONLY},
            proposals=[self.simple_proposal]
        )
        self.assertEqual(sa.doi, Ikev1Doi.GDOI)

    def test_parse_single_proposal(self):
        parsed: Ikev1PayloadSecurityAssociation = Ikev1PayloadSecurityAssociation.parse_exact_size(
            self.test_bytes_single_proposal
        )

        self.assertEqual(parsed.next_payload, Ikev1PayloadType.NONE)
        self.assertEqual(parsed.doi, Ikev1Doi.IPSEC)
        self.assertEqual(parsed.situation, {Ikev1Situation.SIT_IDENTITY_ONLY})
        self.assertEqual(len(parsed.proposals), 1)
        self.assertEqual(parsed.proposals[0].protocol_id, Ikev1ProtocolId.ISAKMP)

    def test_parse_multiple_proposals(self):
        parsed: Ikev1PayloadSecurityAssociation = Ikev1PayloadSecurityAssociation.parse_exact_size(
            self.test_bytes_multi_proposals
        )

        self.assertEqual(parsed.doi, Ikev1Doi.IPSEC)
        self.assertEqual(len(parsed.proposals), 2)
        self.assertEqual(parsed.proposals[0].protocol_id, Ikev1ProtocolId.ISAKMP)
        self.assertEqual(parsed.proposals[1].protocol_id, Ikev1ProtocolId.IPSEC_ESP)

    def test_parse_situation_flags(self):
        parsed: Ikev1PayloadSecurityAssociation = Ikev1PayloadSecurityAssociation.parse_exact_size(
            self.test_bytes_secrecy_integrity
        )

        self.assertEqual(parsed.situation, {Ikev1Situation.SIT_SECRECY, Ikev1Situation.SIT_INTEGRITY})

    def test_compose_single_proposal(self):
        composed_bytes = self.sa_single.compose()
        self.assertEqual(composed_bytes, self.test_bytes_single_proposal)

    def test_compose_multiple_proposals(self):
        composed_bytes = self.sa_multi.compose()
        self.assertEqual(composed_bytes, self.test_bytes_multi_proposals)

    def test_compose_situation_flags(self):
        composed_bytes = self.sa_flags.compose()
        self.assertEqual(composed_bytes, self.test_bytes_secrecy_integrity)

    def test_round_trip_single_proposal(self):
        composed_bytes = self.sa_single.compose()
        parsed: Ikev1PayloadSecurityAssociation = Ikev1PayloadSecurityAssociation.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.doi, self.sa_single.doi)
        self.assertEqual(parsed.situation, self.sa_single.situation)
        self.assertEqual(len(parsed.proposals), len(self.sa_single.proposals))
        self.assertEqual(parsed.next_payload, self.sa_single.next_payload)

    def test_round_trip_multiple_proposals(self):
        composed_bytes = self.sa_multi.compose()
        parsed: Ikev1PayloadSecurityAssociation = Ikev1PayloadSecurityAssociation.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.doi, self.sa_multi.doi)
        self.assertEqual(len(parsed.proposals), len(self.sa_multi.proposals))
        # Verify proposal chaining (first proposal points to next, last to NONE)
        self.assertEqual(parsed.proposals[0].next_payload, Ikev1PayloadType.PROPOSAL)
        self.assertEqual(parsed.proposals[1].next_payload, Ikev1PayloadType.NONE)

    def test_round_trip_situation_flags(self):
        composed_bytes = self.sa_flags.compose()
        parsed: Ikev1PayloadSecurityAssociation = Ikev1PayloadSecurityAssociation.parse_exact_size(composed_bytes)

        self.assertEqual(parsed.situation, self.sa_flags.situation)

    def test_proposal_numbering_in_compose(self):
        composed_bytes = self.sa_multi.compose()

        # Verify proposal numbers are written correctly (1-based indexing)
        self.assertEqual(composed_bytes[16], 1)  # First proposal number at byte 16
        self.assertEqual(composed_bytes[32], 2)  # Second proposal number at byte 32


if __name__ == '__main__':
    unittest.main()
