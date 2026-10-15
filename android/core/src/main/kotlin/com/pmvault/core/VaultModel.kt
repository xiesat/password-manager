package com.pmvault.core

import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/** 把 org.json 结构转成普通 Kotlin 类型（Map/List），供规范化与合并使用。 */
object JsonValues {
    fun convert(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> {
            val map = LinkedHashMap<String, Any?>()
            for (key in value.keys()) map[key] = convert(value.get(key))
            map
        }
        is JSONArray -> (0 until value.length()).map { convert(value.get(it)) }
        else -> value
    }

    fun toRecord(value: Any?): Record {
        val converted = convert(value)
        @Suppress("UNCHECKED_CAST")
        return LinkedHashMap(converted as? Map<String, Any?> ?: emptyMap())
    }

    fun toRecordList(array: JSONArray?): List<Record> =
        if (array == null) emptyList() else (0 until array.length()).map { toRecord(array.get(it)) }

    fun toHistory(obj: JSONObject?): Map<String, List<Any?>> {
        if (obj == null) return emptyMap()
        val result = linkedMapOf<String, List<Any?>>()
        for (name in obj.keys()) {
            val raw = convert(obj.get(name))
            @Suppress("UNCHECKED_CAST")
            result[name] = (raw as? List<Any?>) ?: emptyList()
        }
        return result
    }
}

/** schema 4 载荷。 */
class VaultPayload(
    val schema: Int,
    val vaultId: String,
    val deviceId: String,
    val rev: Long,
    val mainData: List<Record>,
    val tombstones: List<Record>,
    val history: Map<String, List<Any?>>,
    val syncBase: Map<String, String>,
) {
    fun toJson(): JSONObject {
        val root = JSONObject()
        root.put("schema", schema)
        root.put("vault_id", vaultId)
        root.put("device_id", deviceId)
        root.put("rev", rev)
        root.put("mainData", JSONArray(mainData.map { JSONObject(it as Map<*, *>) }))
        root.put("tombstones", JSONArray(tombstones.map { JSONObject(it as Map<*, *>) }))
        val historyJson = JSONObject()
        for ((name, entries) in history) historyJson.put(name, JSONArray(entries))
        root.put("historyData", historyJson)
        root.put("sync_base", JSONObject(syncBase as Map<*, *>))
        return root
    }

    fun toText(): String = toJson().toString()

    companion object {
        fun parse(text: String): VaultPayload = fromJson(JSONObject(text))

        fun fromJson(root: JSONObject): VaultPayload {
            val base = mutableMapOf<String, String>()
            root.optJSONObject("sync_base")?.let { obj ->
                for (key in obj.keys()) base[key] = obj.optString(key, "")
            }
            return VaultPayload(
                schema = root.optInt("schema", 4),
                vaultId = root.optString("vault_id", ""),
                deviceId = root.optString("device_id", ""),
                rev = root.optLong("rev", 0L),
                mainData = normalizeRecords(root.optJSONArray("mainData")),
                tombstones = normalizeRecords(root.optJSONArray("tombstones")),
                history = JsonValues.toHistory(root.optJSONObject("historyData")),
                syncBase = base,
            )
        }

        /** 兼容旧格式（schema < 4，中文键名）。 */
        private fun normalizeRecords(array: JSONArray?): List<Record> {
            if (array == null) return emptyList()
            return (0 until array.length()).mapNotNull { index ->
                val raw = array.optJSONObject(index) ?: return@mapNotNull null
                if (raw.has("id")) {
                    JsonValues.toRecord(raw)
                } else {
                    val name = raw.optString("密码生成主体", "")
                    if (name.isEmpty()) return@mapNotNull null
                    val record: Record = LinkedHashMap()
                    record["id"] = UUID.randomUUID().toString().replace("-", "")
                    record["name"] = name
                    record["password"] = raw.optString("密码", "")
                    record["rule"] = raw.optString("规则", "")
                    record["count"] = raw.optString("第n次生成的密码", "0")
                    record["updated_at"] = raw.optString("更新时间", "")
                    record["hlc"] = ""
                    record["deleted"] = false
                    record
                }
            }
        }
    }
}

/** 内存中的库状态；负责统一合并入口。 */
class VaultState(
    var vaultId: String,
    val deviceId: String,
    var rev: Long = 0,
    var records: MutableList<Record> = mutableListOf(),
    var tombstones: MutableList<Record> = mutableListOf(),
    var history: MutableMap<String, List<Any?>> = mutableMapOf(),
    var syncBase: MutableMap<String, String> = mutableMapOf(),
) {
    private val hlc = Hlc(deviceId)

    fun allRecords(): List<Record> = records + tombstones
    fun contentHash(): String = Merge.contentHash(allRecords())
    fun nextHlc(): String = hlc.next()

    /** 把对端载荷三方合并进本机，返回冲突列表。 */
    fun mergeRemote(remote: VaultPayload): List<Conflict> {
        val remoteRecords = remote.mainData + remote.tombstones
        for (record in remoteRecords) hlc.observe(Merge.recordHlc(record))

        val result = Merge.mergeRecords(syncBase, allRecords(), remoteRecords, vaultId)
        records = result.records.filter { !Merge.isDeleted(it) }.toMutableList()
        tombstones = result.records.filter { Merge.isDeleted(it) }.toMutableList()
        history = Merge.mergeHistory(history, remote.history).toMutableMap()
        syncBase = result.base.toMutableMap()
        rev += 1
        return result.conflicts
    }

    fun toPayload(): VaultPayload =
        VaultPayload(4, vaultId, deviceId, rev, records, tombstones, history, syncBase)

    companion object {
        fun fromPayload(payload: VaultPayload, deviceId: String): VaultState = VaultState(
            vaultId = payload.vaultId.ifEmpty { UUID.randomUUID().toString().replace("-", "") },
            deviceId = deviceId,
            rev = payload.rev,
            records = payload.mainData.toMutableList(),
            tombstones = payload.tombstones.toMutableList(),
            history = payload.history.toMutableMap(),
            syncBase = payload.syncBase.toMutableMap(),
        )
    }
}
