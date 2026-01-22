"""Unit tests for JWT utilities."""

import pytest
from datetime import timedelta
from pathlib import Path

from gimlet.jwt import parse_duration
from gimlet.cli import _validate_signing_key_options


class TestParseDuration:
    """Tests for parse_duration function."""

    def test_valid_seconds(self):
        assert parse_duration("60s") == timedelta(seconds=60)
        assert parse_duration("1s") == timedelta(seconds=1)
        assert parse_duration("0s") == timedelta(seconds=0)

    def test_valid_minutes(self):
        assert parse_duration("30m") == timedelta(minutes=30)
        assert parse_duration("1m") == timedelta(minutes=1)
        assert parse_duration("0m") == timedelta(minutes=0)

    def test_valid_hours(self):
        assert parse_duration("24h") == timedelta(hours=24)
        assert parse_duration("1h") == timedelta(hours=1)
        assert parse_duration("0h") == timedelta(hours=0)

    def test_valid_days(self):
        assert parse_duration("7d") == timedelta(days=7)
        assert parse_duration("1d") == timedelta(days=1)
        assert parse_duration("0d") == timedelta(days=0)

    def test_case_insensitive_unit(self):
        assert parse_duration("24H") == timedelta(hours=24)
        assert parse_duration("30M") == timedelta(minutes=30)
        assert parse_duration("7D") == timedelta(days=7)
        assert parse_duration("60S") == timedelta(seconds=60)

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            parse_duration("")

    def test_invalid_unit_raises(self):
        with pytest.raises(ValueError, match="Invalid duration unit"):
            parse_duration("24x")
        with pytest.raises(ValueError, match="Invalid duration unit"):
            parse_duration("24")
        with pytest.raises(ValueError, match="Invalid duration unit"):
            parse_duration("24w")  # weeks not supported

    def test_missing_value_raises(self):
        with pytest.raises(ValueError, match="numeric value"):
            parse_duration("h")
        with pytest.raises(ValueError, match="numeric value"):
            parse_duration("m")

    def test_non_numeric_value_raises(self):
        with pytest.raises(ValueError, match="Must be an integer"):
            parse_duration("abch")
        with pytest.raises(ValueError, match="Must be an integer"):
            parse_duration("12.5h")  # floats not supported

    def test_negative_value_raises(self):
        with pytest.raises(ValueError, match="non-negative"):
            parse_duration("-1h")
        with pytest.raises(ValueError, match="non-negative"):
            parse_duration("-24h")


class TestValidateSigningKeyOptions:
    """Tests for _validate_signing_key_options function."""

    def test_valid_kms_key_only(self):
        """KMS key alone should pass validation."""
        _validate_signing_key_options(None, "arn:aws:kms:us-east-1:123:key/test")

    def test_valid_private_key_only(self):
        """Private key file alone should pass validation."""
        _validate_signing_key_options(Path("/some/key.pem"), None)

    def test_both_options_raises(self):
        """Both options provided should raise error."""
        with pytest.raises(SystemExit):
            _validate_signing_key_options(
                Path("/some/key.pem"), "arn:aws:kms:us-east-1:123:key/test"
            )

    def test_neither_option_raises(self):
        """No options provided should raise error."""
        with pytest.raises(SystemExit):
            _validate_signing_key_options(None, None)

    def test_empty_kms_string_raises(self):
        """Empty KMS string (e.g., from unset env var) should raise error."""
        with pytest.raises(SystemExit):
            _validate_signing_key_options(None, "")
