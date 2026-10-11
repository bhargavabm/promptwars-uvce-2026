"""Pytest configuration and session reporting hooks for Bankism tests."""

import pytest


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Print pass count and test execution summary at the end of the test run."""
    passed = len(terminalreporter.stats.get("passed", []))
    failed = len(terminalreporter.stats.get("failed", []))
    skipped = len(terminalreporter.stats.get("skipped", []))
    total = passed + failed + skipped

    terminalreporter.write_sep("=", "BANKISM TEST SUMMARY", green=True, bold=True)
    terminalreporter.write_line(f"PASSED TESTS COUNT: {passed} / {total}")
    if failed > 0:
        terminalreporter.write_line(f"FAILED TESTS COUNT: {failed}", red=True)
    if skipped > 0:
        terminalreporter.write_line(f"SKIPPED TESTS COUNT: {skipped}", yellow=True)
    terminalreporter.write_sep("=", f"TOTAL EXECUTED: {total}", green=True, bold=True)
