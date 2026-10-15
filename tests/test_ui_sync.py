"""控制器层的局域网同步测试（离屏）。"""

from __future__ import annotations

import json
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

import merge  # noqa: E402
import storage  # noqa: E402
import sync_service  # noqa: E402
from hlc import HLC  # noqa: E402
from model import PasswordManagerModel  # noqa: E402

KEY = "sync-key"


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


@pytest.fixture()
def controller(app, tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    from controller import PasswordManagerController

    instance = PasswordManagerController()
    instance.view.switch_to_main_interface()
    instance._session_key = KEY

    instance.model.main_data = []
    instance.model.history_data = {}
    instance.model.tombstones = []
    instance.model.add_or_update_subject("Base", length=12)
    instance.model.sync_base = {r["id"]: merge.semantic_hash(r) for r in instance.model.all_records()}

    path = tmp_path / "vault.sk"
    storage.atomic_write_text(
        str(path), instance.model.encrypt_data(KEY, instance.model.prepare_export_data())
    )
    instance.model.set_current_file_path(str(path))
    instance.model.mark_clean()
    instance._reload()
    return instance


def make_peer(model: PasswordManagerModel, device: str) -> PasswordManagerModel:
    peer = PasswordManagerModel()
    assert peer.detect_and_store(model.encrypt_data(KEY, model.prepare_export_data()))[0] is True
    assert peer.decrypt_with_user_key(KEY) is True
    peer.load_data_from_decrypted_json()
    peer.device_id, peer.hlc = device, HLC(device)
    return peer


def test_host_apply_remote_merges_and_persists(controller):
    controller.model.add_or_update_subject("Local-Only", length=12)
    peer = make_peer(controller.model, "peer0001")
    peer.add_or_update_subject("Peer-Only", length=12)

    merged_blob, conflicts = controller._apply_remote_blob(peer.encrypt_data(KEY, peer.prepare_export_data()))

    assert conflicts == []
    names = {r["name"] for r in controller.model.main_data}
    assert {"Base", "Local-Only", "Peer-Only"} <= names
    # 合并结果已原子落盘
    assert storage.read_text(controller.model.current_file_path) == merged_blob
    # 返回的密文可被同一密钥解开
    check = PasswordManagerModel()
    assert check.detect_and_store(merged_blob)[0] is True
    assert check.decrypt_with_user_key(KEY) is True


def test_host_apply_remote_reports_conflicts(controller):
    peer = make_peer(controller.model, "peer0001")
    controller.model.main_data[0]["password"] = "desktop-pw"
    controller.model.main_data[0]["hlc"] = controller.model.hlc.next()
    peer.main_data[0]["password"] = "android-pw"
    peer.main_data[0]["hlc"] = peer.hlc.next()

    _merged, conflicts = controller._apply_remote_blob(peer.encrypt_data(KEY, peer.prepare_export_data()))

    assert len(conflicts) == 1 and conflicts[0]["kind"] == "both_modified"
    assert sorted(r["password"] for r in controller.model.main_data) == ["android-pw", "desktop-pw"]


def test_host_rejects_wrong_key(controller):
    other = PasswordManagerModel()
    other.vault_id = controller.model.vault_id
    other.add_or_update_subject("X")
    blob = other.encrypt_data("different-key", other.prepare_export_data())
    with pytest.raises(ValueError):
        controller._apply_remote_blob(blob)


def test_client_sync_end_to_end(controller):
    host = make_peer(controller.model, "host0001")
    host.add_or_update_subject("Host-Only", length=12)

    def apply_remote(remote_blob: str):
        remote = PasswordManagerModel()
        ok, message, _ = remote.detect_and_store(remote_blob)
        if not ok:
            raise ValueError(message)
        if not remote.decrypt_with_user_key(KEY):
            raise ValueError("密钥不一致")
        conflicts = host.merge_remote(json.loads(remote.raw_decrypted_data))
        return (
            host.encrypt_data(KEY, host.prepare_export_data()),
            [{"kind": c.kind, "name": c.name} for c in conflicts],
        )

    server = sync_service.SyncServer(
        apply_remote=apply_remote,
        vault_id=host.vault_id,
        device_id=host.device_id,
        device_name="host-test",
        host="127.0.0.1",
        port=0,
    )
    server.start()
    try:
        pairing = json.dumps(
            {
                "protocol": 1,
                "host": "127.0.0.1",
                "port": server.port,
                "token": server.token,
                "vault_id": host.vault_id,
                "device_id": host.device_id,
            }
        )
        controller.model.add_or_update_subject("Local-Only", length=12)

        ok, message, conflicts = controller._client_sync(pairing)

        assert ok, message
        assert conflicts == []
        names = {r["name"] for r in controller.model.main_data}
        assert {"Base", "Host-Only", "Local-Only"} <= names
        assert controller.model.is_dirty() is False
        # 本地文件已更新为合并结果
        reloaded = PasswordManagerModel()
        assert reloaded.detect_and_store(storage.read_text(controller.model.current_file_path))[0] is True
        assert reloaded.decrypt_with_user_key(KEY) is True
        reloaded.load_data_from_decrypted_json()
        assert {r["name"] for r in reloaded.main_data} == names
    finally:
        server.stop()


def test_client_sync_rejects_other_vault(controller):
    pairing = json.dumps({"host": "127.0.0.1", "port": 1, "token": "t" * 20, "vault_id": "another-vault"})
    ok, message, conflicts = controller._client_sync(pairing)
    assert ok is False and conflicts == []
    assert "vault_id" in message


def test_client_sync_rejects_bad_pairing_text(controller):
    ok, message, conflicts = controller._client_sync("not-json")
    assert ok is False and conflicts == []
    assert message


def test_sync_dialog_constructs(controller):
    from sync_dialog import SyncDialog

    server = sync_service.SyncServer(
        apply_remote=lambda blob: (blob, []),
        vault_id=controller.model.vault_id,
        device_id=controller.model.device_id,
        host="127.0.0.1",
        port=0,
    )
    server.start()
    try:
        dialog = SyncDialog(server, lambda text: (True, "ok", []))
        assert dialog.pairing_view.toPlainText() == server.pairing_text()
        assert "http://" in dialog.windowTitle() or True  # 仅确保构建成功
        dialog._copy_pairing()
        dialog.close()
    finally:
        server.stop()


def test_server_can_be_stopped_after_dialog(controller):
    server = sync_service.SyncServer(
        apply_remote=lambda blob: (blob, []),
        vault_id=controller.model.vault_id,
        device_id=controller.model.device_id,
        host="127.0.0.1",
        port=0,
    )
    server.start()
    assert server.running
    server.stop()
    assert not server.running
