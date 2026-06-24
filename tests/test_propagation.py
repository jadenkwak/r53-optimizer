"""Unit tests — propagation helpers (wait_for_insync, batch_changes, upsert_record)."""
import pytest
from unittest.mock import MagicMock, call, patch

from dns_tool.propagation import (
    _normalize_change_id,
    batch_changes,
    upsert_record,
    wait_for_insync,
)


ZONE_ID = "Z1234567890ABC"
CHANGE_ID = "/change/C1234567890"


# ── _normalize_change_id ──────────────────────────────────────────────────────

def test_normalize_already_has_prefix():
    assert _normalize_change_id("/change/C123") == "/change/C123"


def test_normalize_adds_prefix():
    assert _normalize_change_id("C123") == "/change/C123"


def test_normalize_strips_extra_slash():
    assert _normalize_change_id("/C123") == "/change/C123"


# ── wait_for_insync ───────────────────────────────────────────────────────────

def test_wait_returns_true_immediately_on_insync():
    client = MagicMock()
    client.get_change.return_value = {"ChangeInfo": {"Status": "INSYNC"}}

    result = wait_for_insync(CHANGE_ID, client=client, poll_interval=0)

    assert result is True
    client.get_change.assert_called_once_with(Id=CHANGE_ID)


def test_wait_polls_until_insync():
    client = MagicMock()
    client.get_change.side_effect = [
        {"ChangeInfo": {"Status": "PENDING"}},
        {"ChangeInfo": {"Status": "PENDING"}},
        {"ChangeInfo": {"Status": "INSYNC"}},
    ]

    result = wait_for_insync(CHANGE_ID, client=client, poll_interval=0)

    assert result is True
    assert client.get_change.call_count == 3


def test_wait_normalizes_change_id_without_prefix():
    client = MagicMock()
    client.get_change.return_value = {"ChangeInfo": {"Status": "INSYNC"}}

    wait_for_insync("C1234567890", client=client, poll_interval=0)

    client.get_change.assert_called_once_with(Id="/change/C1234567890")


def test_wait_raises_timeout_error():
    client = MagicMock()
    # Always PENDING — should time out
    client.get_change.return_value = {"ChangeInfo": {"Status": "PENDING"}}

    with pytest.raises(TimeoutError, match="PENDING"):
        wait_for_insync(CHANGE_ID, client=client, poll_interval=0, timeout=0)


def test_wait_raises_on_api_error():
    from botocore.exceptions import ClientError

    client = MagicMock()
    client.get_change.side_effect = ClientError(
        {"Error": {"Code": "NoSuchChange", "Message": "Not found"}}, "GetChange"
    )

    with pytest.raises(RuntimeError, match="GetChange API call failed"):
        wait_for_insync(CHANGE_ID, client=client, poll_interval=0)


# ── batch_changes ─────────────────────────────────────────────────────────────

def test_batch_changes_returns_change_id():
    client = MagicMock()
    client.change_resource_record_sets.return_value = {
        "ChangeInfo": {"Id": CHANGE_ID, "Status": "PENDING"}
    }

    change = {"Action": "UPSERT", "ResourceRecordSet": {
        "Name": "www.example.com", "Type": "A", "TTL": 300,
        "ResourceRecords": [{"Value": "1.2.3.4"}],
    }}

    result = batch_changes(ZONE_ID, [change], comment="test", client=client)

    assert result == CHANGE_ID
    client.change_resource_record_sets.assert_called_once_with(
        HostedZoneId=ZONE_ID,
        ChangeBatch={"Comment": "test", "Changes": [change]},
    )


def test_batch_changes_raises_on_empty_list():
    with pytest.raises(ValueError, match="empty"):
        batch_changes(ZONE_ID, [], client=MagicMock())


def test_batch_changes_raises_on_api_error():
    from botocore.exceptions import ClientError

    client = MagicMock()
    client.change_resource_record_sets.side_effect = ClientError(
        {"Error": {"Code": "InvalidInput", "Message": "Bad"}}, "ChangeResourceRecordSets"
    )

    with pytest.raises(RuntimeError, match="ChangeResourceRecordSets failed"):
        batch_changes(ZONE_ID, [{"Action": "UPSERT", "ResourceRecordSet": {}}], client=client)


# ── upsert_record ─────────────────────────────────────────────────────────────

def test_upsert_record_calls_batch_and_wait():
    client = MagicMock()
    client.change_resource_record_sets.return_value = {
        "ChangeInfo": {"Id": CHANGE_ID, "Status": "PENDING"}
    }
    client.get_change.return_value = {"ChangeInfo": {"Status": "INSYNC"}}

    change_id = upsert_record(
        ZONE_ID, "www.example.com", "A", ["1.2.3.4"],
        ttl=60, wait=True, client=client
    )

    assert change_id == CHANGE_ID
    client.change_resource_record_sets.assert_called_once()
    client.get_change.assert_called_once()


def test_upsert_record_no_wait():
    client = MagicMock()
    client.change_resource_record_sets.return_value = {
        "ChangeInfo": {"Id": CHANGE_ID, "Status": "PENDING"}
    }

    change_id = upsert_record(
        ZONE_ID, "www.example.com", "A", ["1.2.3.4"],
        wait=False, client=client
    )

    assert change_id == CHANGE_ID
    client.get_change.assert_not_called()


def test_upsert_record_sends_correct_payload():
    client = MagicMock()
    client.change_resource_record_sets.return_value = {
        "ChangeInfo": {"Id": CHANGE_ID, "Status": "PENDING"}
    }

    upsert_record(
        ZONE_ID, "mail.example.com", "MX", ["10 mail.example.com."],
        ttl=3600, wait=False, client=client
    )

    _, kwargs = client.change_resource_record_sets.call_args
    changes = kwargs["ChangeBatch"]["Changes"]
    assert len(changes) == 1
    rrs = changes[0]["ResourceRecordSet"]
    assert rrs["Type"] == "MX"
    assert rrs["TTL"] == 3600
    assert rrs["ResourceRecords"] == [{"Value": "10 mail.example.com."}]
