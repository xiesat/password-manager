package com.pmvault.app

import android.content.Context
import com.pmvault.core.Conflict
import com.pmvault.core.PairingInfo
import com.pmvault.core.PasswordGenerator
import com.pmvault.core.Record
import com.pmvault.core.SyncClient
import com.pmvault.core.SyncException
import com.pmvault.core.VaultCipher
import com.pmvault.core.VaultPayload
import com.pmvault.core.VaultState
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * 密码库仓库：负责文件读写、加解密与（本地）增删改。
 *
 * 所有耗时操作（PBKDF2 60 万次、网络）都应由调用方放到 IO 线程。
 */
class VaultRepository(private val context: Context) {

    private val prefs = context.getSharedPreferences("pmvault", Context.MODE_PRIVATE)

    /** 仅在内存中保存主密钥；锁屏/退出即清除。 */
    var password: String? = null
        private set

    var state: VaultState? = null
        private set

    val vaultFile: File get() = File(context.filesDir, "vault.sk")

    val deviceId: String
        get() {
            prefs.getString("device_id", null)?.let { return it }
            val generated = UUID.randomUUID().toString().replace("-", "").substring(0, 8)
            prefs.edit().putString("device_id", generated).apply()
            return generated
        }

    fun exists(): Boolean = vaultFile.exists()

    fun create(password: String): VaultState {
        val created = VaultState(
            vaultId = UUID.randomUUID().toString().replace("-", ""),
            deviceId = deviceId,
        )
        this.password = password
        this.state = created
        persist()
        return created
    }

    fun unlock(password: String): VaultState {
        val text = vaultFile.readText(Charsets.UTF_8)
        val payload = VaultPayload.parse(VaultCipher.decrypt(password, text))
        val opened = VaultState.fromPayload(payload, deviceId)
        this.password = password
        this.state = opened
        return opened
    }

    fun lock() {
        password = null
        state = null
    }

    fun persist() {
        val key = password ?: throw IllegalStateException("尚未解锁")
        val current = state ?: throw IllegalStateException("尚未解锁")
        vaultFile.writeText(VaultCipher(key).encrypt(current.toPayload().toText()), Charsets.UTF_8)
    }

    fun addEntry(
        name: String,
        length: Int,
        lower: Boolean,
        upper: Boolean,
        digit: Boolean,
        symbol: Boolean,
    ): Record {
        val current = state ?: throw IllegalStateException("尚未解锁")
        val generated = PasswordGenerator.generateV2(name, length, lower, upper, digit, symbol)

        val existingIndex = current.records.indexOfFirst { it["name"] == name }
        val identifier = if (existingIndex >= 0) {
            current.records[existingIndex]["id"] as? String ?: newId()
        } else {
            newId()
        }

        val record: Record = linkedMapOf(
            "id" to identifier,
            "name" to name,
            "password" to generated.first,
            "rule" to PasswordGenerator.buildRule(length, lower, upper, digit, symbol, generated.second),
            "count" to "0",
            "updated_at" to timestamp(),
            "hlc" to current.nextHlc(),
            "deleted" to false,
        )

        if (existingIndex >= 0) {
            current.records[existingIndex] = record
        } else {
            current.records.add(record)
        }
        current.rev += 1
        persist()
        return record
    }

    fun deleteEntries(indexes: List<Int>) {
        val current = state ?: throw IllegalStateException("尚未解锁")
        for (index in indexes.sortedDescending()) {
            if (index < 0 || index >= current.records.size) continue
            val item = current.records.removeAt(index)
            val tombstone: Record = linkedMapOf(
                "id" to (item["id"] ?: newId()),
                "name" to (item["name"] as? String ?: ""),
                "password" to "",
                "rule" to "",
                "count" to (item["count"] as? String ?: "0"),
                "updated_at" to timestamp(),
                "hlc" to current.nextHlc(),
                "deleted" to true,
            )
            current.tombstones.add(tombstone)
        }
        current.rev += 1
        persist()
    }

    /**
     * 与另一台设备（通常是桌面端）同步：
     * 把本机密文发给主机，采用主机返回的合并结果并落盘。
     */
    fun sync(pairingText: String): List<Conflict> {
        val key = password ?: throw IllegalStateException("尚未解锁")
        val current = state ?: throw IllegalStateException("尚未解锁")

        val pairing = PairingInfo.parse(pairingText)
        if (pairing.vaultId != current.vaultId) {
            throw SyncException("对方的密码库与本机不是同一个（vault_id 不一致）")
        }

        val localBlob = VaultCipher(key).encrypt(current.toPayload().toText())
        val mergedBlob = SyncClient(pairing).sync(localBlob)
        val mergedPayload = VaultPayload.parse(VaultCipher.decrypt(key, mergedBlob))

        val conflicts = current.mergeRemote(mergedPayload)
        vaultFile.writeText(mergedBlob, Charsets.UTF_8)
        state = VaultState.fromPayload(mergedPayload, deviceId)
        return conflicts
    }

    private fun newId(): String = UUID.randomUUID().toString().replace("-", "")

    private fun timestamp(): String =
        SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
}
