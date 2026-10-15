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

    /** 历史密码条目；密码由规则确定性还原得到。 */
    data class HistoryEntry(val password: String, val count: String, val time: String)

    /**
     * 为已有主体**重新生成**密码：沿用原规则的长度与字符类型，换一个新盐。
     * 与桌面端 generate_new_password_for_subject 语义一致（次数 +1、旧密码写入历史）。
     */
    fun regenerate(index: Int): Record {
        val current = state ?: throw IllegalStateException("尚未解锁")
        if (index < 0 || index >= current.records.size) throw IllegalArgumentException("记录不存在")
        val item = current.records[index]
        val name = item["name"] as? String ?: ""

        val spec = PasswordGenerator.parseRule(item["rule"] as? String ?: "")
            ?: PasswordGenerator.parseRule(PasswordGenerator.defaultRule())
            ?: throw IllegalStateException("无法解析密码规则")

        val generated = PasswordGenerator.generateV2(
            name, spec.length, spec.lower, spec.upper, spec.digit, spec.symbol, null,
        )
        val count = ((item["count"] as? String)?.toIntOrNull() ?: 0) + 1
        val rule = PasswordGenerator.buildRule(
            spec.length, spec.lower, spec.upper, spec.digit, spec.symbol, generated.second,
        )

        // 关键：替换成**新的 Map 实例**而不是原地改。
        // 原地修改会让新旧 records 列表「结构相等」，Compose 判定没变化 → 界面不刷新。
        val updated: Record = LinkedHashMap(item)
        updated["password"] = generated.first
        updated["rule"] = rule
        updated["count"] = count.toString()
        updated["updated_at"] = timestamp()
        updated["hlc"] = current.nextHlc()
        current.records[index] = updated

        addHistory(name, count.toString(), rule)
        current.rev += 1
        persist()
        return updated
    }

    /** 原始历史条目（还没还原出密码），用于逐条计算并汇报进度。 */
    fun rawHistory(name: String): List<List<Any?>> {
        val current = state ?: return emptyList()
        return (current.history[name] ?: emptyList()).mapNotNull { entry ->
            (entry as? List<Any?>)?.takeIf { it.size >= 2 }
        }
    }

    /**
     * 还原**一条**历史密码：一次 20 万次 PBKDF2。
     * 调用方必须放到后台线程，并据此显示进度。
     * 无法还原的旧格式条目返回 null。
     */
    fun deriveHistoryEntry(name: String, row: List<Any?>): HistoryEntry? {
        val count = row[0] as? String ?: return null
        val rule = row[1] as? String ?: return null
        val time = (row.getOrNull(2) as? String) ?: ""
        val spec = PasswordGenerator.parseRule(rule) ?: return null
        val restored = PasswordGenerator.regenerate(name, spec) ?: return null
        return HistoryEntry(restored, count, time)
    }

    private fun addHistory(name: String, count: String, rule: String) {
        val current = state ?: return
        val entry: List<Any?> = listOf(count, rule, timestamp())
        val existing: List<Any?> = current.history[name] ?: emptyList()
        current.history[name] = listOf<Any?>(entry) + existing
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
     * 首次加入：从桌面端下载整库密文，用 [password] 解密后作为本机库保存。
     * 注意：会覆盖本机现有的库。
     */
    fun importFromHost(pairingText: String, password: String): VaultState {
        val pairing = PairingInfo.parse(pairingText)
        val blob = SyncClient(pairing).fetchVault()
        val payload = VaultPayload.parse(VaultCipher.decrypt(password, blob))

        vaultFile.writeText(blob, Charsets.UTF_8)
        this.password = password
        val opened = VaultState.fromPayload(payload, deviceId)
        this.state = opened
        return opened
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
