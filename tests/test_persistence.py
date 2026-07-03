"""
Unit tests: persistence layer (SQLite investigation store).
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
import tempfile
import json
from pathlib import Path

from watson.persistence.models import (
    Investigation, InvestigationStatus, InvestigationStep, StepStatus,
)
from watson.persistence.store import InvestigationStore


class TestModels:
    def test_investigation_defaults(self):
        inv = Investigation(original_query="test query")
        assert inv.original_query == "test query"
        assert inv.status == InvestigationStatus.CREATED
        assert inv.investigation_id  # auto-generated
        assert inv.total_hops == 0
        assert inv.total_findings == 0

    def test_investigation_roundtrip(self):
        inv = Investigation(
            investigation_id="test-123",
            original_query="find this",
            status=InvestigationStatus.COMPLETED,
            target_type="domain",
            target_value="example.com",
            total_hops=3,
            total_findings=12,
            confirmed_count=5,
        )
        row = inv.to_row()
        inv2 = Investigation.from_row(row)
        assert inv2.investigation_id == "test-123"
        assert inv2.original_query == "find this"
        assert inv2.status == InvestigationStatus.COMPLETED
        assert inv2.total_hops == 3

    def test_step_roundtrip(self):
        step = InvestigationStep(
            step_id="step-1",
            investigation_id="inv-1",
            hop_number=0,
            agent="recon",
            query="example.com",
            target_type="domain",
            status=StepStatus.COMPLETED,
            findings_json='[{"title": "test"}]',
        )
        row = step.to_row()
        step2 = InvestigationStep.from_row(row)
        assert step2.step_id == "step-1"
        assert step2.status == StepStatus.COMPLETED


class TestInvestigationStore:
    @pytest.fixture
    def store(self):
        """Create store with temp database."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            s = InvestigationStore(db_path)
            yield s
            # Cleanup happens when tmpdir is deleted

    def test_create_investigation(self, store):
        inv = store.create("test query")
        assert inv.investigation_id
        assert inv.original_query == "test query"
        assert inv.status == InvestigationStatus.CREATED
        assert inv.created_at

    def test_get_investigation(self, store):
        inv = store.create("find domain")
        retrieved = store.get(inv.investigation_id)
        assert retrieved is not None
        assert retrieved.original_query == "find domain"

    def test_get_nonexistent(self, store):
        assert store.get("nonexistent") is None

    def test_update_investigation(self, store):
        inv = store.create("query")
        inv.status = InvestigationStatus.COMPLETED
        inv.total_hops = 2
        inv.total_findings = 5
        inv.confirmed_count = 3
        store.update(inv)

        retrieved = store.get(inv.investigation_id)
        assert retrieved.status == InvestigationStatus.COMPLETED
        assert retrieved.total_hops == 2
        assert retrieved.total_findings == 5

    def test_list_recent(self, store):
        store.create("query 1")
        store.create("query 2")
        store.create("query 3")
        recent = store.list_recent(limit=2)
        assert len(recent) == 2
        assert recent[0].original_query == "query 3"  # Most recent first

    def test_get_active(self, store):
        inv1 = store.create("active 1")
        inv2 = store.create("completed")
        inv2.status = InvestigationStatus.COMPLETED
        store.update(inv2)

        active = store.get_active()
        assert len(active) >= 1
        assert any(a.investigation_id == inv1.investigation_id for a in active)

    def test_add_and_get_steps(self, store):
        inv = store.create("multi-hop")
        step1 = InvestigationStep(
            investigation_id=inv.investigation_id,
            hop_number=0,
            agent="recon",
            query="example.com",
            status=StepStatus.COMPLETED,
            findings_json='[{"title": "dns"}]',
        )
        step2 = InvestigationStep(
            investigation_id=inv.investigation_id,
            hop_number=1,
            agent="corporate",
            query="Example Inc",
            status=StepStatus.FAILED,
        )
        store.add_step(step1)
        store.add_step(step2)

        steps = store.get_steps(inv.investigation_id)
        assert len(steps) == 2
        assert steps[0].hop_number == 0
        assert steps[1].agent == "corporate"

    def test_update_step(self, store):
        inv = store.create("test")
        step = InvestigationStep(
            investigation_id=inv.investigation_id,
            hop_number=0,
            agent="recon",
            status=StepStatus.RUNNING,
        )
        store.add_step(step)

        step.status = StepStatus.COMPLETED
        step.findings_json = '[{"title": "done"}]'
        store.update_step(step)

        steps = store.get_steps(inv.investigation_id)
        assert steps[0].status == StepStatus.COMPLETED

    def test_get_full_investigation(self, store):
        inv = store.create("full test")
        store.add_step(InvestigationStep(
            investigation_id=inv.investigation_id,
            hop_number=0, agent="recon", status=StepStatus.COMPLETED,
        ))

        retrieved_inv, steps = store.get_full_investigation(inv.investigation_id)
        assert retrieved_inv is not None
        assert len(steps) == 1

    def test_get_full_nonexistent(self, store):
        inv, steps = store.get_full_investigation("nonexistent")
        assert inv is None
        assert steps == []

    def test_get_stats(self, store):
        store.create("q1")
        inv = store.create("q2")
        inv.status = InvestigationStatus.COMPLETED
        inv.total_findings = 5
        inv.confirmed_count = 3
        store.update(inv)

        stats = store.get_stats()
        assert stats["total_investigations"] == 2
        assert stats["completed"] == 1
        assert stats["total_findings"] == 5
        assert stats["confirmed_findings"] == 3

    def test_persistence_survives_reopen(self, store):
        """Data persists across store re-initialization."""
        inv = store.create("survive restart")
        store.add_step(InvestigationStep(
            investigation_id=inv.investigation_id,
            hop_number=0, agent="recon", status=StepStatus.COMPLETED,
        ))

        # Re-open with same db path
        db_path = store.db_path
        store2 = InvestigationStore(db_path)
        retrieved = store2.get(inv.investigation_id)
        assert retrieved is not None
        assert retrieved.original_query == "survive restart"

        steps = store2.get_steps(inv.investigation_id)
        assert len(steps) == 1
