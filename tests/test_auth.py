"""
End-to-end auth flow tests — verifies the full credential validation →
session token → live analysis pipeline using mocked AWS calls.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from fastapi.testclient import TestClient

from api.main import _sessions, app

client = TestClient(app, raise_server_exceptions=True)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_client_error(code: str, message: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": message}},
        "GetCallerIdentity",
    )


def _mock_sts_success(account_id: str = "123456789012") -> MagicMock:
    """Return a mock STS client that reports valid credentials."""
    sts = MagicMock()
    sts.get_caller_identity.return_value = {
        "Account": account_id,
        "Arn": f"arn:aws:iam::{account_id}:user/dns-operator",
        "UserId": "AIDAIOSFODNN7EXAMPLE",
    }
    return sts


def _mock_session(sts_client: MagicMock) -> MagicMock:
    session = MagicMock()
    session.client.return_value = sts_client
    return session


# ── /api/auth  POST ───────────────────────────────────────────────────────────

class TestAuthEndpoint:

    def test_valid_credentials_return_token_and_account_id(self):
        sts = _mock_sts_success()
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            res = client.post("/api/auth", json={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
            })

        assert res.status_code == 200
        body = res.json()
        assert "token" in body
        assert len(body["token"]) > 20          # non-trivial random token
        assert body["account_id"] == "123456789012"
        assert "arn:aws:iam::123456789012" in body["arn"]

    def test_valid_credentials_stored_in_session(self):
        sts = _mock_sts_success()
        _sessions.clear()
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            res = client.post("/api/auth", json={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
            })

        token = res.json()["token"]
        assert token in _sessions
        assert _sessions[token].access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert _sessions[token].region == "us-east-1"

    def test_invalid_key_id_returns_401_with_clear_message(self):
        sts = MagicMock()
        sts.get_caller_identity.side_effect = _make_client_error(
            "InvalidClientTokenId",
            "The security token included in the request is invalid.",
        )
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            res = client.post("/api/auth", json={
                "access_key_id": "AKIAINVALID",
                "secret_access_key": "secret",
                "region": "us-east-1",
            })

        assert res.status_code == 401
        assert "Access Key ID is invalid" in res.json()["detail"]

    def test_wrong_secret_key_returns_401_with_clear_message(self):
        sts = MagicMock()
        sts.get_caller_identity.side_effect = _make_client_error(
            "SignatureDoesNotMatch",
            "The request signature we calculated does not match.",
        )
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            res = client.post("/api/auth", json={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wrongsecret",
                "region": "us-east-1",
            })

        assert res.status_code == 401
        assert "Secret Access Key is incorrect" in res.json()["detail"]

    def test_access_denied_returns_401(self):
        sts = MagicMock()
        sts.get_caller_identity.side_effect = _make_client_error(
            "AccessDenied",
            "User is not authorized to perform sts:GetCallerIdentity",
        )
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            res = client.post("/api/auth", json={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "secret",
                "region": "us-east-1",
            })

        assert res.status_code == 401
        assert "Access denied" in res.json()["detail"]

    def test_credentials_are_stripped_of_whitespace(self):
        """Pasted credentials often have trailing spaces or newlines."""
        sts = _mock_sts_success()
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            res = client.post("/api/auth", json={
                "access_key_id": "  AKIAIOSFODNN7EXAMPLE  ",
                "secret_access_key": "  wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
                "region": "us-east-1",
            })

        assert res.status_code == 200
        token = res.json()["token"]
        assert _sessions[token].access_key_id == "AKIAIOSFODNN7EXAMPLE"
        assert _sessions[token].secret_access_key == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    def test_each_login_issues_a_unique_token(self):
        sts = _mock_sts_success()
        tokens = []
        for _ in range(3):
            with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
                res = client.post("/api/auth", json={
                    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "region": "us-east-1",
                })
            tokens.append(res.json()["token"])

        assert len(set(tokens)) == 3, "Every login must produce a distinct token"


# ── /api/auth/status  GET ─────────────────────────────────────────────────────

class TestAuthStatus:

    def test_no_token_returns_invalid(self):
        res = client.get("/api/auth/status")
        assert res.json() == {"valid": False, "mode": None}

    def test_garbage_token_returns_invalid(self):
        res = client.get("/api/auth/status", headers={"X-Session-Token": "notavalidtoken"})
        assert res.json()["valid"] is False

    def test_valid_session_token_returns_valid(self):
        sts = _mock_sts_success()
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            auth_res = client.post("/api/auth", json={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
            })
        token = auth_res.json()["token"]

        status_res = client.get("/api/auth/status", headers={"X-Session-Token": token})
        assert status_res.json() == {"valid": True, "mode": "live"}


# ── /api/auth  DELETE ─────────────────────────────────────────────────────────

class TestLogout:

    def test_logout_removes_session(self):
        sts = _mock_sts_success()
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            token = client.post("/api/auth", json={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
            }).json()["token"]

        assert token in _sessions
        client.request("DELETE", "/api/auth", headers={"X-Session-Token": token})
        assert token not in _sessions

    def test_logout_without_token_is_harmless(self):
        res = client.request("DELETE", "/api/auth")
        assert res.status_code == 200


# ── Full flow: auth → live analysis ──────────────────────────────────────────

class TestLiveAnalysisWithSession:

    def _login(self) -> str:
        sts = _mock_sts_success()
        with patch("api.r53_client.boto3.Session", return_value=_mock_session(sts)):
            return client.post("/api/auth", json={
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "region": "us-east-1",
            }).json()["token"]

    def test_session_token_used_for_analysis(self):
        """After login, X-Session-Token must reach the Route 53 client."""
        token = self._login()

        mock_r53 = MagicMock()
        # Paginator returns one zone page
        zone_paginator = MagicMock()
        zone_paginator.paginate.return_value = [{
            "HostedZones": [{
                "Id": "/hostedzone/ZTEST123",
                "Name": "mycompany.com.",
                "Config": {"PrivateZone": False, "Comment": "prod"},
                "ResourceRecordSetCount": 5,
            }]
        }]
        # Records paginator — includes a CNAME to AWS that should trigger a finding
        record_paginator = MagicMock()
        record_paginator.paginate.return_value = [{
            "ResourceRecordSets": [
                {
                    "Name": "mycompany.com.",
                    "Type": "SOA", "TTL": 900,
                    "ResourceRecords": [{"Value": "ns1.example.com. admin.example.com. 1 3600 900 86400 300"}],
                },
                {
                    "Name": "www.mycompany.com.",
                    "Type": "CNAME", "TTL": 300,
                    "ResourceRecords": [{"Value": "d123.cloudfront.net"}],
                },
            ]
        }]

        def paginator_factory(name):
            if name == "list_hosted_zones":
                return zone_paginator
            return record_paginator

        mock_r53.get_paginator.side_effect = paginator_factory

        mock_session = MagicMock()
        mock_session.client.return_value = mock_r53

        with patch("api.r53_client.boto3.Session", return_value=mock_session):
            res = client.get("/api/analysis", headers={"X-Session-Token": token})

        assert res.status_code == 200
        data = res.json()
        assert data["zone_count"] == 1
        assert data["zones"][0]["zone_name"] == "mycompany.com."

        # CNAME_TO_AWS_ENDPOINT finding must fire
        rule_ids = [f["rule_id"] for f in data["zones"][0]["findings"]]
        assert "CNAME_TO_AWS_ENDPOINT" in rule_ids

    def test_analysis_without_token_and_without_demo_returns_error(self):
        """No session and no ?demo=true should not silently succeed."""
        from unittest.mock import patch
        from botocore.exceptions import NoCredentialsError

        mock_r53 = MagicMock()
        mock_r53.get_paginator.side_effect = NoCredentialsError()
        mock_session = MagicMock()
        mock_session.client.return_value = mock_r53

        with patch("api.r53_client.boto3.Session", return_value=mock_session):
            res = client.get("/api/analysis")

        assert res.status_code == 500
