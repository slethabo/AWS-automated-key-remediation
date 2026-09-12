from key_remediation.cli import main
from tests.conftest import key_status


def test_cli_deactivates_key(iam, user_with_key, capsys):
    user_name, key_id = user_with_key

    exit_code = main([key_id], iam_client=iam)

    assert exit_code == 0
    assert key_status(iam, user_name, key_id) == "Inactive"
    assert user_name in capsys.readouterr().out


def test_cli_invalid_format_exits_2(iam, capsys):
    exit_code = main(["nope"], iam_client=iam)
    assert exit_code == 2
    assert "Invalid" in capsys.readouterr().err


def test_cli_unknown_key_exits_1(iam, capsys):
    exit_code = main(["AKIAZZZZZZZZZZZZZZZZ"], iam_client=iam)
    assert exit_code == 1
    assert "not found" in capsys.readouterr().err
