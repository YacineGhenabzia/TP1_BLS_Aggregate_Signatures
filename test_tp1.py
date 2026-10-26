"""Automated correctness tests for the TP1 educational implementation."""
import unittest

from bls_core import (
    aggregate_signatures,
    canonical_json_bytes,
    generate_keypair,
    sign_message,
    validate_registry_entry,
    verify_aggregate,
    verify_message,
)


class AggregateSignatureTests(unittest.TestCase):
    def setUp(self):
        self.secret_keys = []
        self.public_keys = []
        self.messages = []
        self.signatures = []
        for i in range(3):
            sk, pk, pop = generate_keypair()
            self.assertTrue(validate_registry_entry(pk, pop))
            message = canonical_json_bytes({"device_id": f"sensor-{i}", "value": 20 + i})
            signature = sign_message(sk, message)
            self.secret_keys.append(sk)
            self.public_keys.append(pk)
            self.messages.append(message)
            self.signatures.append(signature)

    def test_valid_individual_signature(self):
        self.assertTrue(verify_message(self.public_keys[0], self.messages[0], self.signatures[0]))

    def test_modified_message_fails(self):
        changed = canonical_json_bytes({"device_id": "sensor-0", "value": 999})
        self.assertFalse(verify_message(self.public_keys[0], changed, self.signatures[0]))

    def test_aggregate_valid(self):
        aggregate = aggregate_signatures(self.signatures)
        self.assertTrue(verify_aggregate(self.public_keys, self.messages, aggregate))

    def test_aggregate_tampered_message_fails(self):
        aggregate = aggregate_signatures(self.signatures)
        altered = list(self.messages)
        altered[1] = canonical_json_bytes({"device_id": "sensor-1", "value": -100})
        self.assertFalse(verify_aggregate(self.public_keys, altered, aggregate))

    def test_wrong_public_key_fails(self):
        aggregate = aggregate_signatures(self.signatures)
        _, wrong_pk, _ = generate_keypair()
        wrong_pks = list(self.public_keys)
        wrong_pks[0] = wrong_pk
        self.assertFalse(verify_aggregate(wrong_pks, self.messages, aggregate))


if __name__ == "__main__":
    unittest.main(verbosity=2)
