"""Tests for ARGUS Attack Corpus."""

import tempfile
from pathlib import Path

from argus.corpus.manager import AttackCategory, AttackCorpus, AttackPattern


def test_corpus_seeds_on_first_load():
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus = AttackCorpus(corpus_dir=Path(tmpdir) / "corpus")
        count = corpus.load()
        assert count > 0
        assert corpus.size > 0


def test_corpus_query_by_category():
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus = AttackCorpus(corpus_dir=Path(tmpdir) / "corpus")
        corpus.load()

        pi_patterns = corpus.get_patterns(category=AttackCategory.PROMPT_INJECTION_DIRECT)
        assert len(pi_patterns) > 0
        for p in pi_patterns:
            assert p.category == AttackCategory.PROMPT_INJECTION_DIRECT


def test_corpus_query_by_agent_type():
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus = AttackCorpus(corpus_dir=Path(tmpdir) / "corpus")
        corpus.load()

        patterns = corpus.get_patterns(agent_type="prompt_injection_hunter")
        assert len(patterns) > 0


def test_corpus_record_usage():
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus = AttackCorpus(corpus_dir=Path(tmpdir) / "corpus")
        corpus.load()

        patterns = corpus.get_patterns()
        first = patterns[0]

        corpus.record_usage(first.id, successful=True)
        corpus.record_usage(first.id, successful=False)

        updated = corpus.get_pattern(first.id)
        assert updated is not None
        assert updated.times_used == 2
        assert updated.times_successful == 1
        assert updated.success_rate == 0.5


def test_corpus_add_pattern():
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus = AttackCorpus(corpus_dir=Path(tmpdir) / "corpus")
        corpus.load()
        initial_size = corpus.size

        corpus.add_pattern(
            AttackPattern(
                id="custom-001",
                name="Custom test pattern",
                category=AttackCategory.PROMPT_INJECTION_DIRECT,
                description="A custom pattern",
                template="Custom payload: {payload}",
                tags=["custom"],
            )
        )

        assert corpus.size == initial_size + 1
        assert corpus.get_pattern("custom-001") is not None


def test_corpus_save_and_reload():
    with tempfile.TemporaryDirectory() as tmpdir:
        corpus_dir = Path(tmpdir) / "corpus"

        corpus1 = AttackCorpus(corpus_dir=corpus_dir)
        corpus1.load()
        corpus1.add_pattern(
            AttackPattern(
                id="persist-001",
                name="Persistent pattern",
                category=AttackCategory.TOOL_POISONING_DESCRIPTION,
                description="Tests persistence",
                template="Test {payload}",
            )
        )
        corpus1.save()

        corpus2 = AttackCorpus(corpus_dir=corpus_dir)
        corpus2.load()
        assert corpus2.get_pattern("persist-001") is not None
