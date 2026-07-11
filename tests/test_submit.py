"""Submit-URL tests."""
# pylint: disable=missing-function-docstring,redefined-outer-name

import urllib.parse

from glinet4_profiler.submit import REGISTRY_REPO, prefilled_issue_url

PROFILE = {
    "id": "mt6000_4.9.0",
    "model": "mt6000",
    "firmware_version": "4.9.0",
    "services": {"system": {"get_info": {"status": "available", "covered_by": "router_info"}}},
}


def test_prefilled_issue_url_points_at_form():
    url = prefilled_issue_url(PROFILE)
    assert url.startswith(f"https://github.com/{REGISTRY_REPO}/issues/new?")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    assert query["template"][0] == "profile-submission.yml"
    assert "mt6000" in query["title"][0] and "4.9.0" in query["title"][0]
