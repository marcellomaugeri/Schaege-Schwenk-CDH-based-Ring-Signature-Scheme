import re

import pytest
from typer.testing import CliRunner

from demo import app


@pytest.fixture
def pairing_options():
    return ["--type", "a", "--rbits", "160", "--qbits", "512"]


def test_help():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    help_text = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
    for option in (
        "--type",
        "--rbits",
        "--qbits",
        "--hash",
        "--users",
        "--signer",
        "--message",
    ):
        assert option in help_text
    assert "--message-length" not in help_text


@pytest.mark.parametrize("hash_name", ["sha256", "sha512"])
def test_demo(pairing_options, hash_name):
    result = CliRunner().invoke(
        app,
        [
            *pairing_options,
            "--hash",
            hash_name,
            "--users",
            "3",
            "--signer",
            "2",
            "--message",
            "Hello",
        ],
    )
    assert result.exit_code == 0, result.output
    assert "Valid signature: True" in result.stdout
    assert "Modified message accepted: False" in result.stdout


def test_invalid_arguments(pairing_options):
    runner = CliRunner()
    for args in (
        ["--users", "0"],
        ["--users", "2", "--signer", "2"],
        ["--signer", "-1"],
        ["--message-length", "256"],
    ):
        assert runner.invoke(app, [*pairing_options, *args]).exit_code == 2
    assert runner.invoke(app, []).exit_code == 2
    assert runner.invoke(app, [*pairing_options, "--hash", "unknown-hash"]).exit_code == 2
    result = runner.invoke(app, [*pairing_options, "--hash", "shake_256"])
    assert result.exit_code == 2
    assert "fixed-output" in result.output
