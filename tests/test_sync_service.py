"""局域网同步服务测试：HKDF / 签名 / 认证 / 端到端同步。"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import pytest

import merge
import sync_service
from hlc import HLC
from model import PasswordManagerModel
from sync_service import (
    SyncClient,
    SyncError,
    SyncServer,
    derive_auth_key,
    hkdf_sha256,
    lan_ip,
    make_qr_png,
    sign_request,
)

KEY = "vault-key"


# ============================================================ HKDF / 签名
def test_hkdf_matches_rfc5869_test_case_1():
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )
    assert hkdf_sha256(ikm, salt=salt, info=info, length=42) == expected


def test_auth_key_is_stable_and_token_dependent():
    assert derive_auth_key("tok", "vid") == derive_auth_key("tok", "vid")
    assert derive_auth_key("tok", "vid") != derive_auth_key("tok2", "vid")
    assert derive_auth_key("tok", "vid") != derive_auth_key("tok", "vid2")


def test_signature_detects_tampering():
    key = derive_auth_key("tok", "vid")
    body = b'{"vault":"x"}'
    signature = sign_request(key, timestamp="1", nonce="n" * 16, method="POST", path="/sync", body=body)
    assert sync_service.verify_signature(
        key, signature, timestamp="1", nonce="n" * 16, method="POST", path="/sync", body=body
    )
    for mutated in (
        {"body": b'{"vault":"y"}'},
        {"path": "/other"},
        {"method": "GET"},
        {"nonce": "m" * 16},
        {"timestamp": "2"},
    ):
        args = {"timestamp": "1", "nonce": "n" * 16, "method": "POST", "path": "/sync", "body": body}
        args.update(mutated)
        assert not sync_service.verify_signature(key, signature, **args)


def test_lan_ip_looks_like_an_address():
    value = lan_ip()
    assert isinstance(value, str) and value.count(".") == 3


# ============================================================ 测试脚手架
def build_models() -> tuple[PasswordManagerModel, PasswordManagerModel]:
    a = PasswordManagerModel()
    a.add_or_update_subject("Base", length=12)
    payload = a.prepare_export_data()

    b = PasswordManagerModel()
    assert b.detect_and_store(a.encrypt_data(KEY, payload))[0] is True
    assert b.decrypt_with_user_key(KEY) is True
    b.load_data_from_decrypted_json()

    snapshot = {r["id"]: merge.semantic_hash(r) for r in a.all_records()}
    a.sync_base = dict(snapshot)
    b.sync_base = dict(snapshot)
    a.device_id, a.hlc = "aaaa0001", HLC("aaaa0001")
    b.device_id, b.hlc = "bbbb0002", HLC("bbbb0002")
    return a, b


def payload_of(model: PasswordManagerModel) -> dict:
    return json.loads(model.raw_decrypted_data) if model.raw_decrypted_data else model.prepare_export_data()


def make_server(host_model: PasswordManagerModel) -> tuple[SyncServer, list]:
    seen_conflicts: list = []

    def apply_remote(remote_blob: str):
        remote_model = PasswordManagerModel()
        ok, _msg, _ver = remote_model.detect_and_store(remote_blob)
        if not ok:
            raise ValueError("对端文件格式不合法")
        if not remote_model.decrypt_with_user_key(KEY):
            raise ValueError("对端使用了不同的密钥")
        conflicts = host_model.merge_remote(json.loads(remote_model.raw_decrypted_data))
        seen_conflicts.extend(conflicts)
        merged_blob = host_model.encrypt_data(KEY, host_model.prepare_export_data())
        return merged_blob, [{"kind": c.kind, "name": c.name, "copy_id": c.copy_id} for c in conflicts]

    server = SyncServer(
        apply_remote=apply_remote,
        vault_id=host_model.vault_id,
        device_id=host_model.device_id,
        device_name="desktop-test",
        host="127.0.0.1",
        port=0,
    )
    server.start()
    return server, seen_conflicts


@pytest.fixture()
def synced_server():
    a, b = build_models()
    server, conflicts = make_server(a)
    try:
        yield a, b, server, conflicts
    finally:
        server.stop()


# ============================================================ 端到端
def test_info_endpoint_reports_vault(synced_server):
    a, _b, server, _conflicts = synced_server
    info = SyncClient(host="127.0.0.1", port=server.port, token=server.token, vault_id=a.vault_id).info()
    assert info["vault_id"] == a.vault_id
    assert info["protocol"] == sync_service.PAIRING_PROTOCOL_VERSION


def test_end_to_end_sync_converges_and_keeps_both_edits(synced_server):
    a, b, server, conflicts = synced_server

    b.add_or_update_subject("Android-Only")
    a.add_or_update_subject("Desktop-Only")

    client = SyncClient(host="127.0.0.1", port=server.port, token=server.token, vault_id=a.vault_id)
    result = client.sync(b.encrypt_data(KEY, b.prepare_export_data()))

    # 客户端把主机返回的合并结果落回本地
    merged = PasswordManagerModel()
    assert merged.detect_and_store(result["vault"])[0] is True
    assert merged.decrypt_with_user_key(KEY) is True
    merged.load_data_from_decrypted_json()

    assert {r["name"] for r in merged.main_data} == {"Base", "Android-Only", "Desktop-Only"}
    assert a.content_hash() == merged.content_hash()


def test_end_to_end_same_record_conflict_keeps_both(synced_server):
    a, b, server, conflicts = synced_server

    a.main_data[0]["password"] = "desktop-pw"
    a.main_data[0]["hlc"] = a.hlc.next()
    a._mark_dirty()
    b.main_data[0]["password"] = "android-pw"
    b.main_data[0]["hlc"] = b.hlc.next()
    b._mark_dirty()

    client = SyncClient(host="127.0.0.1", port=server.port, token=server.token, vault_id=a.vault_id)
    result = client.sync(b.encrypt_data(KEY, b.prepare_export_data()))

    merged = PasswordManagerModel()
    merged.detect_and_store(result["vault"])
    merged.decrypt_with_user_key(KEY)
    merged.load_data_from_decrypted_json()

    assert sorted(r["password"] for r in merged.main_data) == ["android-pw", "desktop-pw"]
    assert result["conflicts"] and result["conflicts"][0]["kind"] == "both_modified"
    assert a.content_hash() == merged.content_hash()


def test_wrong_token_is_rejected(synced_server):
    a, b, server, _conflicts = synced_server
    client = SyncClient(host="127.0.0.1", port=server.port, token="wrong-token", vault_id=a.vault_id)
    with pytest.raises(SyncError):
        client.sync(b.encrypt_data(KEY, b.prepare_export_data()))


def test_replayed_request_is_rejected(synced_server):
    a, b, server, _conflicts = synced_server
    body = json.dumps({"vault": b.encrypt_data(KEY, b.prepare_export_data())}).encode("utf-8")
    timestamp = str(int(time.time() * 1000))
    nonce = "deadbeefdeadbeef"
    signature = sign_request(
        server.auth_key, timestamp=timestamp, nonce=nonce, method="POST", path="/sync", body=body
    )
    headers = {
        "Content-Type": "application/json",
        "X-PM-Timestamp": timestamp,
        "X-PM-Nonce": nonce,
        "X-PM-Signature": signature,
    }
    url = f"http://127.0.0.1:{server.port}/sync"

    first = urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers))
    assert first.status == 200
    first.close()

    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(urllib.request.Request(url, data=body, headers=headers))
    assert excinfo.value.code == 401


@pytest.mark.parametrize("tamper", ["stale", "future"])
def test_stale_or_future_timestamp_is_rejected(synced_server, tamper):
    a, b, server, _conflicts = synced_server
    body = json.dumps({"vault": b.encrypt_data(KEY, b.prepare_export_data())}).encode("utf-8")
    offset = -10 * 60 * 1000 if tamper == "stale" else 10 * 60 * 1000
    timestamp = str(int(time.time() * 1000) + offset)
    nonce = "cafebabecafebabe"
    signature = sign_request(
        server.auth_key, timestamp=timestamp, nonce=nonce, method="POST", path="/sync", body=body
    )
    request = urllib.request.Request(
        f"http://127.0.0.1:{server.port}/sync",
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-PM-Timestamp": timestamp,
            "X-PM-Nonce": nonce,
            "X-PM-Signature": signature,
        },
    )
    with pytest.raises(urllib.error.HTTPError) as excinfo:
        urllib.request.urlopen(request)
    assert excinfo.value.code == 401


# ============================================================ 配对与二维码
def test_pairing_payload_roundtrip(synced_server):
    a, _b, server, _conflicts = synced_server
    text = server.pairing_text()
    payload = json.loads(text)
    assert payload["vault_id"] == a.vault_id
    assert payload["port"] == server.port

    client = SyncClient.from_pairing_text(text)
    assert client.host and client.port == server.port and client.token == server.token


def test_pairing_text_rejects_bad_input():
    with pytest.raises(SyncError):
        SyncClient.from_pairing_text("not json")
    with pytest.raises(SyncError):
        SyncClient.from_pairing_text('{"host":"1.2.3.4"}')


def test_qr_png_is_generated(tmp_path):
    target = tmp_path / "pairing.png"
    result = make_qr_png('{"host":"1.2.3.4"}', str(target))
    assert result == str(target)
    assert target.exists() and target.stat().st_size > 0


def test_server_stop_is_idempotent(synced_server):
    _a, _b, server, _conflicts = synced_server
    assert server.running is True
    server.stop()
    server.stop()
    assert server.running is False
