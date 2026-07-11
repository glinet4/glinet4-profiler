"""Registry fetch-client tests."""
# pylint: disable=missing-function-docstring,redefined-outer-name

from glinet4_profiler.registry import lookup

MAN = {"devices": [{"id": "mt6000_4.9.0", "model": "mt6000", "firmware_version": "4.9.0"}]}


def test_lookup_match_miss_and_none():
    assert lookup("mt6000", "4.9.0", MAN) is not None
    assert lookup("mt6000", "4.9.0", MAN)["id"] == "mt6000_4.9.0"  # type: ignore[index]
    assert lookup("mt6000", "9.9.9", MAN) is None
    assert lookup("mt6000", "4.9.0", None) is None
