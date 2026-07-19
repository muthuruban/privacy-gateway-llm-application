"""
Module purpose
--------------

Detect PII in text (Microsoft Presidio + a custom UK National Insurance
number recognizer) and apply the configured privacy policy: tokenize,
redact, allow — with BLOCK handled by the caller before any text is
transformed.

Security responsibility
-----------------------

* Detection covers *every* entity type in the policy, including ALLOW
  entities, so the audit trail can distinguish "no PII found" from "PII
  found and deliberately allowed".
* Tokenization goes through the request-scoped TokenizationContext, so
  values in different messages of one request can never collide.
* Redaction is irreversible by construction: no mapping is kept.

Important limitation
--------------------

Detection is statistical. Recognizers miss entities (false negatives)
and mislabel text (false positives); anything the detector misses is
forwarded untouched regardless of policy. This limitation is inherited
by every guarantee built on top of this module.
"""

from __future__ import annotations

from typing import Any

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from .policy import DEFAULT_POLICY, PolicyAction
from .tokenization import TokenizationContext

# UK National Insurance number, e.g. "AB 12 34 56 C". Not shipped with
# Presidio, so registered as a custom recognizer. The prefix letter
# classes follow HMRC allocation rules (D, F, I, Q, U, V never appear),
# which is why the well-known example "QQ 12 34 56 C" is *not* matched.
_UK_NINO_PATTERN = Pattern(
    name="uk_nino",
    regex=r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b",
    score=0.6,
)


def _build_uk_nino_recognizer() -> PatternRecognizer:
    return PatternRecognizer(
        supported_entity="UK_NINO",
        name="UkNinoRecognizer",
        patterns=[_UK_NINO_PATTERN],
        context=["nino", "national insurance", "ni number"],
    )


class PIIMediator:
    """Policy-driven PII detector and sanitizer built on Presidio."""

    def __init__(
        self,
        policy: dict[str, PolicyAction] | None = None,
        score_threshold: float = 0.4,
        language: str = "en",
        spacy_model: str = "en_core_web_sm",
    ) -> None:
        self.policy = dict(policy) if policy is not None else dict(DEFAULT_POLICY)
        self.score_threshold = score_threshold
        self.language = language

        nlp_engine = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": language, "model_name": spacy_model}],
            }
        ).create_engine()
        self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[language])
        self.analyzer.registry.add_recognizer(_build_uk_nino_recognizer())
        self.anonymizer = AnonymizerEngine()

    def clone_with_policy(self, policy: dict[str, PolicyAction]) -> PIIMediator:
        """A mediator with a different policy that shares the (expensive)
        NLP engines. The engines are stateless between calls."""
        clone = object.__new__(PIIMediator)
        clone.policy = dict(policy)
        clone.score_threshold = self.score_threshold
        clone.language = self.language
        clone.analyzer = self.analyzer
        clone.anonymizer = self.anonymizer
        return clone

    def analyze(self, text: str) -> list[RecognizerResult]:
        """
        Detect every policy-listed entity type in ``text``.

        Security reason:
            ALLOW entities are deliberately included in the requested
            entity list. Excluding them would make "PII knowingly crossed
            the boundary" indistinguishable from "no PII detected" in the
            audit evidence.
        """
        if not text:
            return []
        return self.analyzer.analyze(
            text=text,
            entities=list(self.policy),
            language=self.language,
            score_threshold=self.score_threshold,
        )

    def apply(
        self,
        text: str,
        results: list[RecognizerResult],
        context: TokenizationContext | None,
    ) -> str:
        """
        Transform ``text`` according to policy: tokenize and redact spans.

        ALLOW detections are left untouched (they only feed the audit
        record). BLOCK detections must have been handled by the caller —
        finding one here means the block check was bypassed, so this
        method fails closed rather than quietly redacting.

        Args:
            text: original message text.
            results: detections from :meth:`analyze` on the same text.
            context: the request's shared tokenization context. Required
                when any TOKENIZE entity is present.

        Returns:
            The provider-safe text.

        Raises:
            RuntimeError: if a BLOCK-policy detection reaches this method,
                or a TOKENIZE detection arrives without a context.
        """
        actionable = []
        for result in results:
            action = self.policy.get(result.entity_type)
            if action is PolicyAction.BLOCK:
                # Security note: BLOCK is not redaction. Reaching this
                # point means the request should already have been
                # rejected; continuing would weaken BLOCK to REDACT.
                raise RuntimeError("BLOCK-policy entity reached sanitization")
            if action in (PolicyAction.TOKENIZE, PolicyAction.REDACT):
                actionable.append(result)

        if not actionable:
            return text

        operators: dict[str, OperatorConfig] = {}
        for entity_type in {r.entity_type for r in actionable}:
            if self.policy[entity_type] is PolicyAction.TOKENIZE:
                if context is None:
                    raise RuntimeError("TOKENIZE requires a TokenizationContext")
                operators[entity_type] = OperatorConfig(
                    "custom", {"lambda": self._make_tokenizer(entity_type, context)}
                )
            else:
                operators[entity_type] = OperatorConfig(
                    "replace", {"new_value": f"[REDACTED:{entity_type}]"}
                )

        # Passing analyzer results to the anonymizer is Presidio's
        # documented usage; its type stubs declare a stricter (internal)
        # result class, hence the targeted ignore.
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=actionable,  # type: ignore[arg-type]
            operators=operators,
        )
        return str(anonymized.text)

    @staticmethod
    def _make_tokenizer(entity_type: str, context: TokenizationContext) -> Any:
        """Per-entity-type operator that mints tokens from the shared
        request context (Presidio's custom operator passes only the
        matched text, so the entity type is bound via this closure)."""

        def _operator(original: str) -> str:
            return context.token_for(entity_type, original)

        return _operator

    def redact_all(self, text: str, results: list[RecognizerResult]) -> str:
        """
        Irreversibly redact *every* detection, regardless of action.

        Used only for the optional research/debug audit-content mode: if
        content is stored at all, every detected entity is removed first.
        Undetected entities can still remain — see module header.
        """
        if not results:
            return text
        operators = {
            entity_type: OperatorConfig("replace", {"new_value": f"[REDACTED:{entity_type}]"})
            for entity_type in {r.entity_type for r in results}
        }
        anonymized = self.anonymizer.anonymize(
            text=text,
            analyzer_results=results,  # type: ignore[arg-type]
            operators=operators,
        )
        return str(anonymized.text)
