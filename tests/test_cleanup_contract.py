"""Tests for the batched expired-session cleanup contract.

These tests run on the in-memory reference implementation but assert the
contract rules every backend must honor: bounded batches, safe interleaving of
renewals and deletes, interruption/resume, conditional-delete semantics,
count-only logging and fail-closed capability gating.
"""

import logging
from datetime import datetime, timedelta, timezone

import pytest
from flask_session.cleanup import (
    BatchCleanupStore,
    CleanupConfig,
    InMemorySessionStore,
    StaleWriteError,
    UnsafeCleanupError,
    all_assessments,
    assess_backend,
    ensure_cleanup_supported,
    require_batch_cleanup_store,
    resume_cleanup,
    run_cleanup,
)

UTC = timezone.utc
T0 = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)
SECRET_MARKERS = ("topsecret", "payload-value", "permission:admin")


def make_store(expired=0, live=0, *, expiry_offset_minutes=1):
    store = InMemorySessionStore()
    for i in range(expired):
        store.upsert_session(
            f"session:{i:04d}",
            {"secret": f"topsecret-{i}", "scope": "payload-value"},
            T0 - timedelta(minutes=expiry_offset_minutes),
        )
    for i in range(live):
        store.upsert_session(
            f"session:live-{i:04d}",
            {"secret": "topsecret-live"},
            T0 + timedelta(minutes=10),
        )
    return store


def record_count(store):
    return store.size


class TestBatchLimits:
    def test_batch_size_is_a_hard_scan_ceiling(self):
        store = make_store(expired=10)
        config = CleanupConfig(batch_size=4)

        observed_limits = []
        original_scan = store.scan_expired_sessions

        def spying_scan(**kwargs):
            observed_limits.append(kwargs["limit"])
            assert kwargs["limit"] <= 4
            return original_scan(**kwargs)

        store.scan_expired_sessions = spying_scan
        result = run_cleanup(store, config, now=T0)

        assert observed_limits and all(limit == 4 for limit in observed_limits)
        assert result.deleted == 10
        assert record_count(store) == 0
        # Pages of 4, 4 and 2; the final page terminates without an empty round trip.
        assert result.batches == 3

    def test_max_batches_caps_work_and_returns_resume_cursor(self):
        store = make_store(expired=10)
        result = run_cleanup(
            store, CleanupConfig(batch_size=4, max_batches=1), now=T0
        )

        assert result.batches == 1
        assert result.interrupted is True
        assert result.resume_cursor is not None
        assert result.deleted == 4
        assert record_count(store) == 6

    def test_resume_completes_the_remaining_work(self):
        store = make_store(expired=10)
        first = run_cleanup(
            store, CleanupConfig(batch_size=4, max_batches=1), now=T0
        )
        second = resume_cleanup(
            store, first.resume_cursor, CleanupConfig(batch_size=4), now=T0
        )

        assert second.interrupted is False
        assert second.resume_cursor is None
        assert first.deleted + second.deleted == 10
        assert record_count(store) == 0

    def test_external_interrupt_is_resumable(self):
        store = make_store(expired=9)
        calls = {"n": 0}

        def interrupt_after_two_batches():
            calls["n"] += 1
            return calls["n"] > 2

        first = run_cleanup(
            store,
            CleanupConfig(batch_size=3),
            now=T0,
            should_interrupt=interrupt_after_two_batches,
        )
        assert first.interrupted is True
        assert first.batches == 2
        assert first.deleted == 6

        second = resume_cleanup(
            store, first.resume_cursor, CleanupConfig(batch_size=3), now=T0
        )
        assert second.deleted == 3
        assert record_count(store) == 0


class TestRenewalAndConditionalDelete:
    def test_renewed_record_is_never_deleted(self):
        store = make_store(expired=1)
        store.upsert_session("session:renewed", {"secret": "topsecret-renew"}, T0 - timedelta(minutes=5))

        original_delete = store.delete_session_if_expiry_matches

        def renew_then_delete(store_id, **kwargs):
            if store_id == "session:renewed":
                store.renew_session(store_id, T0 + timedelta(minutes=30))
            return original_delete(store_id, **kwargs)

        store.delete_session_if_expiry_matches = renew_then_delete
        result = run_cleanup(store, CleanupConfig(batch_size=10), now=T0)

        assert result.deleted == 1
        assert result.skipped == 1
        assert store.get_session("session:renewed", now=T0) == {
            "secret": "topsecret-renew"
        }

    def test_conditional_delete_reports_false_for_renewed_and_missing(self):
        store = make_store(expired=2)
        expiry = T0 - timedelta(minutes=1)

        assert (
            store.delete_session_if_expiry_matches(
                "session:0000", expected_expiry=expiry, now=T0
            )
            is True
        )
        # Already removed -> idempotent miss.
        assert (
            store.delete_session_if_expiry_matches(
                "session:0000", expected_expiry=expiry, now=T0
            )
            is False
        )
        # Renewed fence -> condition no longer matches, record survives.
        store.renew_session("session:0001", T0 + timedelta(minutes=5))
        assert (
            store.delete_session_if_expiry_matches(
                "session:0001", expected_expiry=expiry, now=T0
            )
            is False
        )
        assert store.get_session("session:0001", now=T0) is not None

    def test_live_records_are_outside_the_scan_window(self):
        store = make_store(expired=3, live=2)
        result = run_cleanup(store, CleanupConfig(batch_size=100), now=T0)
        assert result.deleted == 3
        assert record_count(store) == 2

    def test_stale_copy_with_older_expiry_is_rejected(self):
        store = InMemorySessionStore()
        store.upsert_session("session:perm", {"scope": "read"}, T0 + timedelta(minutes=10))
        # Current, narrowed record with a later fence.
        store.upsert_session("session:perm", {"scope": "read"}, T0 + timedelta(minutes=20))
        # A delayed stale replica carrying an older, broader copy must not win.
        with pytest.raises(StaleWriteError):
            store.upsert_session(
                "session:perm",
                {"scope": "permission:admin"},
                T0 + timedelta(minutes=5),
            )
        assert store.get_session("session:perm", now=T0) == {"scope": "read"}

    def test_renewal_cannot_regress_expiry(self):
        store = make_store(expired=1)
        with pytest.raises(StaleWriteError):
            store.renew_session("session:0000", T0 - timedelta(minutes=30))


class TestCountOnlyObservability:
    def test_logs_contain_only_counts_never_ids_or_values(self, caplog):
        store = make_store(expired=6, live=2)
        caplog.set_level(logging.INFO, logger="flask_session.cleanup.runner")
        result = run_cleanup(
            store,
            CleanupConfig(batch_size=3, max_batches=1),
            now=T0,
            logger=logging.getLogger("flask_session.cleanup.runner"),
        )
        assert result.scanned == 3
        text = "\n".join(record.getMessage() for record in caplog.records)
        for marker in SECRET_MARKERS:
            assert marker not in text
        assert "session:" not in text
        # Counts are present.
        assert "scanned=3" in text
        assert "deleted=3" in text

    def test_scan_returns_metadata_without_payload_field(self):
        store = make_store(expired=2)
        page = store.scan_expired_sessions(now=T0, limit=10, cursor=None)
        assert len(page.candidates) == 2
        for candidate in page.candidates:
            assert not hasattr(candidate, "value")
            assert not hasattr(candidate, "data")
            assert isinstance(candidate.store_id, str)
            assert candidate.expiry.tzinfo is not None


class TestCapabilityGate:
    def test_in_memory_store_satisfies_protocol(self):
        assert isinstance(InMemorySessionStore(), BatchCleanupStore)

    def test_non_contract_object_is_rejected(self):
        class NotAStore:
            pass

        with pytest.raises(UnsafeCleanupError):
            require_batch_cleanup_store(NotAStore())
        with pytest.raises(UnsafeCleanupError):
            run_cleanup(NotAStore(), now=T0)

    @pytest.mark.parametrize("backend", ["redis", "memcached", "mongodb", "dynamodb", "cachelib", "filesystem"])
    def test_native_ttl_backends_reject_manual_cleanup(self, backend):
        assessment = assess_backend(backend)
        assert assessment.native_ttl is True
        assert assessment.eligible is False
        with pytest.raises(UnsafeCleanupError):
            ensure_cleanup_supported(backend)

    @pytest.mark.parametrize("backend", ["sqlalchemy", "postgresql"])
    def test_non_ttl_backends_are_refused_until_adapter_is_completed(self, backend):
        assessment = assess_backend(backend)
        assert assessment.native_ttl is False
        assert "bounded_scan" in assessment.capabilities.missing()
        assert "conditional_delete" in assessment.capabilities.missing()
        with pytest.raises(UnsafeCleanupError):
            ensure_cleanup_supported(backend)

    def test_unknown_backend_is_refused(self):
        with pytest.raises(UnsafeCleanupError):
            ensure_cleanup_supported("made-up-db")

    def test_every_bundled_backend_has_an_assessment(self):
        backends = {a.backend for a in all_assessments()}
        assert backends == {
            "redis",
            "memcached",
            "filesystem",
            "cachelib",
            "mongodb",
            "dynamodb",
            "sqlalchemy",
            "postgresql",
        }
        assert not any(assessment.eligible for assessment in all_assessments())


class TestConfigValidation:
    def test_invalid_batch_size(self):
        with pytest.raises(ValueError):
            CleanupConfig(batch_size=0)

    def test_invalid_max_batches(self):
        with pytest.raises(ValueError):
            CleanupConfig(max_batches=0)


class TestEdgeCases:
    def test_sweep_over_empty_store_completes_in_one_batch(self):
        result = run_cleanup(InMemorySessionStore(), CleanupConfig(batch_size=10), now=T0)
        assert result.batches == 1
        assert result.as_counts() == {
            "scanned": 0,
            "deleted": 0,
            "skipped": 0,
            "batches": 1,
            "interrupted": False,
        }
        assert result.resume_cursor is None

    def test_naive_datetimes_are_normalized_to_utc(self):
        store = InMemorySessionStore()
        naive_expiry = datetime(2026, 11, 12, 11, 59, 0)  # naive, treated as UTC
        store.upsert_session("session:naive", {"secret": "topsecret"}, naive_expiry)
        page = store.scan_expired_sessions(now=T0, limit=1, cursor=None)
        assert len(page.candidates) == 1
        assert page.candidates[0].expiry == T0.replace(hour=11, minute=59)
        assert page.candidates[0].expiry.utcoffset() == timedelta(0)
        assert (
            store.delete_session_if_expiry_matches(
                "session:naive", expected_expiry=naive_expiry, now=T0
            )
            is True
        )

    def test_resume_is_idempotent_when_cursor_re_delivered(self):
        store = make_store(expired=5)
        first = run_cleanup(
            store, CleanupConfig(batch_size=2, max_batches=1), now=T0
        )
        assert first.deleted == 2
        # Re-running with the same cursor must not resurrect or double-delete.
        again = resume_cleanup(
            store, first.resume_cursor, CleanupConfig(batch_size=2), now=T0
        )
        assert again.deleted == 3
        assert record_count(store) == 0
        tail = resume_cleanup(
            store, again.resume_cursor, CleanupConfig(batch_size=2), now=T0
        )
        assert tail.deleted == 0 and tail.scanned == 0

    def test_scan_never_exceeds_requested_limit(self):
        store = make_store(expired=25)
        page = store.scan_expired_sessions(now=T0, limit=7, cursor=None)
        assert len(page.candidates) <= 7
        assert page.next_cursor == page.candidates[-1].store_id

    def test_clock_edge_keeps_record_when_no_longer_due_at_delete(self):
        store = InMemorySessionStore()
        expiry = T0
        store.upsert_session("session:edge", {"secret": "topsecret"}, expiry)
        # Same fence, but reference time moved before expiry: not due anymore.
        assert (
            store.delete_session_if_expiry_matches(
                "session:edge",
                expected_expiry=expiry,
                now=T0 - timedelta(seconds=1),
            )
            is False
        )
        assert store.size == 1
