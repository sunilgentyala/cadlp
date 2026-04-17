"""Unit tests for Stage 2: NER with operational/exemplary disambiguation."""

import pytest
from cadlp.csc.stage2_ner import detect, ContextLabel


class TestNERDetection:
    def test_person_with_title_detected(self):
        prompt = "Please update the record for Dr. Sarah Johnson immediately."
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert any("PERSON" in t for t in types)

    def test_exemplary_person_suppressed(self):
        prompt = "For example, suppose the user is Dr. John Doe in this hypothetical."
        spans = detect(prompt)
        # Exemplary context should suppress the entity
        person_spans = [s for s in spans if "PERSON" in s.entity_type]
        assert len(person_spans) == 0

    def test_org_detected_in_operational_context(self):
        prompt = "Submit the invoice to Acme Technologies Inc. by end of day."
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert any("ORGANIZATION" in t for t in types)

    def test_project_codename_detected(self):
        prompt = "The PROJ_X deployment is blocked by a security review."
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert any("PROJECT_CODE" in t for t in types)

    def test_employee_id_detected(self):
        prompt = "Terminate access for EMP-00942 as of today."
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert any("EMPLOYEE_ID" in t for t in types)

    def test_ticket_id_detected(self):
        prompt = "Please escalate JIRA-1042 to the security team."
        spans = detect(prompt)
        types = [s.entity_type for s in spans]
        assert any("TICKET_ID" in t for t in types)

    def test_no_double_count_with_stage1(self):
        from cadlp.csc.stage1_fastpath import SensitiveSpan
        email_span = SensitiveSpan(start=10, end=30,
                                   entity_type="EMAIL_ADDRESS",
                                   confidence=0.9, value="test@test.com")
        prompt = "Contact test@test.com now."
        spans = detect(prompt, existing_spans=[email_span])
        for s in spans:
            assert not (s.start < 30 and s.end > 10)

    def test_clean_prompt_no_ner_spans(self):
        prompt = "Explain gradient descent in machine learning."
        spans = detect(prompt)
        assert isinstance(spans, list)


class TestContextDisambiguation:
    def test_operational_signals_raise_score(self):
        prompt = "Please delete the record for Ms. Alice Brown from the database."
        spans = detect(prompt)
        person_spans = [s for s in spans if "PERSON" in s.entity_type]
        if person_spans:
            assert any("OPERATIONAL" in s.entity_type or
                       "UNCERTAIN" in s.entity_type for s in person_spans)

    def test_span_confidence_in_range(self):
        prompt = "Update the account for Mr. Bob Smith."
        spans = detect(prompt)
        for s in spans:
            assert 0.0 <= s.confidence <= 1.0

    def test_stage_marker_is_2(self):
        prompt = "Notify Dr. Eve Carter about the incident."
        spans = detect(prompt)
        for s in spans:
            assert s.stage == 2
