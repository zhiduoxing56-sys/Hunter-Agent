"""Qualified official TRUDI tools exposed by Hunter's minimal full profile."""

from __future__ import annotations


MINIMAL_FULL_TOOLS = frozenset(
    {
        "misc_start_execution_log",
        "misc_record_agent_message",
        "misc_record_disposition",
        "misc_record_finding",
        "misc_export_execution_log",
        "misc_write_final_report",
        "hash_hash_file",
        "hash_verify_evidence_hash",
        "strings_file_identify",
        "strings_stat_file",
        "strings_strings_extract",
        "strings_strings_grep",
        "read_read_output",
        "reason_reason_hypothesize",
        "reason_reason_plan",
        "reason_reason_evaluate_finding",
        "reason_reason_confidence_score",
        "reason_reason_cite_check",
        "reason_reason_synthesize",
        "reason_reason_pre_report_check",
        "dair_dair_assess",
    }
)
