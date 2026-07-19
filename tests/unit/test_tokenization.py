"""Tokenization context: namespace safety, collision-free minting across
messages, and strict exact-match rehydration."""

from __future__ import annotations

import re

import gateway.tokenization as tokenization_module
from gateway.tokenization import TOKEN_PATTERN, TokenizationContext


class TestNamespace:
    def test_namespace_is_eight_uppercase_hex_chars(self):
        ctx = TokenizationContext()
        assert re.fullmatch(r"[0-9A-F]{8}", ctx.namespace)

    def test_namespaces_differ_between_contexts(self):
        namespaces = {TokenizationContext().namespace for _ in range(20)}
        assert len(namespaces) == 20

    def test_namespace_avoids_collision_with_request_text(self, monkeypatch):
        # Force the first candidate to collide with the request text and
        # check that generation retries instead of using it.
        candidates = iter(["deadbeef", "cafe0142"])
        monkeypatch.setattr(tokenization_module.secrets, "token_hex", lambda n: next(candidates))
        ctx = TokenizationContext("this text already contains DEADBEEF somewhere")
        assert ctx.namespace == "CAFE0142"


class TestTokenMinting:
    def test_token_format_matches_pattern(self):
        ctx = TokenizationContext()
        token = ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        assert TOKEN_PATTERN.fullmatch(token)
        assert ctx.namespace in token

    def test_same_value_reuses_token(self):
        ctx = TokenizationContext()
        first = ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        second = ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        assert first == second
        assert len(ctx) == 1

    def test_different_values_get_different_tokens(self):
        # The original defect: alice and bob in different messages both
        # became ..._EMAIL_ADDRESS_1 and one mapping overwrote the other.
        ctx = TokenizationContext()
        alice = ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        bob = ctx.token_for("EMAIL_ADDRESS", "bob@example.com")
        assert alice != bob
        assert ctx.token_to_value[alice] == "alice@example.com"
        assert ctx.token_to_value[bob] == "bob@example.com"

    def test_counters_are_per_entity_type(self):
        ctx = TokenizationContext()
        email = ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        person = ctx.token_for("PERSON", "Alice Johnson")
        assert email.endswith("_EMAIL_ADDRESS_1]]")
        assert person.endswith("_PERSON_1]]")

    def test_contexts_do_not_share_mappings(self):
        first = TokenizationContext()
        second = TokenizationContext()
        token = first.token_for("EMAIL_ADDRESS", "alice@example.com")
        assert token not in second.token_to_value


class TestRehydration:
    def test_known_token_is_restored(self):
        ctx = TokenizationContext()
        token = ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        assert ctx.rehydrate(f"Reply to {token} today") == "Reply to alice@example.com today"

    def test_unknown_token_left_unchanged(self):
        ctx = TokenizationContext()
        ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        fake = "[[PGW_00000000_EMAIL_ADDRESS_9]]"
        assert ctx.rehydrate(f"see {fake}") == f"see {fake}"

    def test_foreign_context_token_left_unchanged(self):
        ours = TokenizationContext()
        theirs = TokenizationContext()
        their_token = theirs.token_for("EMAIL_ADDRESS", "bob@example.com")
        assert ours.rehydrate(their_token) == their_token

    def test_partial_token_left_unchanged(self):
        ctx = TokenizationContext()
        token = ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        truncated = token[:-2]  # strip closing brackets
        assert ctx.rehydrate(truncated) == truncated

    def test_user_text_resembling_token_left_unchanged(self):
        ctx = TokenizationContext()
        lookalike = "[[PGW_NOTHEX_EMAIL_ADDRESS_1]] and [[EMAIL_ADDRESS_1]]"
        assert ctx.rehydrate(lookalike) == lookalike

    def test_multiple_occurrences_all_restored(self):
        ctx = TokenizationContext()
        token = ctx.token_for("PERSON", "Alice Johnson")
        text = f"{token} spoke; later {token} left."
        assert ctx.rehydrate(text) == "Alice Johnson spoke; later Alice Johnson left."

    def test_replacement_is_single_pass(self):
        # A restored value that happens to look like a token must not be
        # replaced again by a second pass.
        ctx = TokenizationContext()
        inner = ctx.token_for("PERSON", "Alice")
        outer = ctx.token_for("EMAIL_ADDRESS", inner)  # value IS a token string
        restored = ctx.rehydrate(outer)
        assert restored == inner  # restored once, not chained to "Alice"


class TestClear:
    def test_clear_removes_all_mappings(self):
        ctx = TokenizationContext()
        token = ctx.token_for("EMAIL_ADDRESS", "alice@example.com")
        ctx.clear()
        assert len(ctx) == 0
        assert ctx.rehydrate(token) == token
