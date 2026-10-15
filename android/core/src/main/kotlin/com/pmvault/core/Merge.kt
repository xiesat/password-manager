package com.pmvault.core

import java.util.UUID

/** 记录 = 与 JSON 一一对应的可变映射，保持字段无损。 */
typealias Record = MutableMap<String, Any?>

data class Conflict(
    val recordId: String,
    val kind: String,
    val winnerId: String,
    val copyId: String?,
    val name: String,
    val origin: String,
)

class MergeResult(
    val records: List<Record>,
    val base: Map<String, String>,
    val conflicts: List<Conflict>,
) {
    val contentHash: String get() = Merge.contentHash(records)
}

/**
 * 三方合并（与 Python 参考实现 merge.py 行为一致）。
 * 见 spec/VAULT_FORMAT.md §6。
 */
object Merge {

    const val HASH_LEN = 32
    const val CONFLICT_SUFFIX = "（冲突副本 %s）"
    val conflictNamespace: UUID = UUID.fromString("6f1a2b3c-4d5e-4f60-8a9b-0c1d2e3f4051")

    fun recordId(record: Map<String, Any?>): String = record["id"] as? String ?: ""
    fun recordHlc(record: Map<String, Any?>): String = record["hlc"] as? String ?: ""
    fun nameOf(record: Map<String, Any?>): String = record["name"] as? String ?: ""
    fun isDeleted(record: Map<String, Any?>): Boolean = record["deleted"] == true

    fun origin(record: Map<String, Any?>): String = recordHlc(record).split("-").getOrNull(2) ?: "?"

    fun semanticPayload(record: Map<String, Any?>): Map<String, Any?> =
        if (isDeleted(record)) {
            mapOf("deleted" to true)
        } else {
            mapOf(
                "name" to nameOf(record),
                "password" to (record["password"] as? String ?: ""),
                "rule" to (record["rule"] as? String ?: ""),
            )
        }

    fun semanticHash(record: Map<String, Any?>): String =
        Crypto.sha256Hex(Json.canonical(semanticPayload(record))).substring(0, HASH_LEN)

    fun contentHash(records: List<Map<String, Any?>>): String {
        val digests = records.map { recordId(it) + ":" + semanticHash(it) }.sorted()
        return Crypto.sha256Hex(digests.joinToString("\n"))
    }

    private fun orderKey(record: Map<String, Any?>): List<String> =
        listOf(recordHlc(record), recordId(record), semanticHash(record))

    private fun compareKeys(a: List<String>, b: List<String>): Int {
        for (index in a.indices) {
            val result = a[index].compareTo(b[index])
            if (result != 0) return result
        }
        return 0
    }

    fun conflictCopy(record: Map<String, Any?>, vaultId: String): Record {
        val copy: Record = LinkedHashMap(record)
        val material = vaultId + ":" + recordId(record) + ":" + recordHlc(record) + ":" + semanticHash(record)
        copy["id"] = Crypto.uuid5(conflictNamespace, material).toString()
        copy["name"] = nameOf(record) + CONFLICT_SUFFIX.format(origin(record))
        copy["deleted"] = false
        copy["conflict_of"] = recordId(record)
        return copy
    }

    private class Resolution(val winner: Record, val copy: Record?, val conflict: Conflict?)

    private fun resolve(left: Record?, right: Record?, vaultId: String): Resolution {
        if (left == null) return Resolution(right!!, null, null)
        if (right == null) return Resolution(left, null, null)

        val leftDead = isDeleted(left)
        val rightDead = isDeleted(right)

        if (leftDead != rightDead) {
            // 删除 vs 编辑：保留活着的版本（宁可多一条，也不丢密码）
            val alive = if (leftDead) right else left
            val dead = if (leftDead) left else right
            return Resolution(
                alive, null,
                Conflict(recordId(alive), "delete_vs_edit", recordId(alive), null, nameOf(alive), origin(dead)),
            )
        }

        if (leftDead && rightDead) {
            val winner = if (compareKeys(orderKey(left), orderKey(right)) >= 0) left else right
            val loser = if (winner === left) right else left
            return Resolution(
                winner, null,
                Conflict(recordId(winner), "both_deleted", recordId(winner), null, nameOf(winner), origin(loser)),
            )
        }

        val winner: Record
        val loser: Record
        if (compareKeys(orderKey(left), orderKey(right)) >= 0) {
            winner = left
            loser = right
        } else {
            winner = right
            loser = left
        }
        val copy = conflictCopy(loser, vaultId)
        return Resolution(
            winner, copy,
            Conflict(recordId(winner), "both_modified", recordId(winner), copy["id"] as String, nameOf(loser), origin(loser)),
        )
    }

    fun mergeRecords(
        base: Map<String, String>?,
        local: List<Record>,
        remote: List<Record>,
        vaultId: String,
    ): MergeResult {
        val baseMap = base ?: emptyMap()
        val localById = local.associateBy { recordId(it) }
        val remoteById = remote.associateBy { recordId(it) }

        val ids = LinkedHashSet<String>()
        ids.addAll(localById.keys)
        ids.addAll(remoteById.keys)
        ids.addAll(baseMap.keys)

        val records = mutableListOf<Record>()
        val newBase = mutableMapOf<String, String>()
        val conflicts = mutableListOf<Conflict>()

        for (id in ids) {
            val left = localById[id]
            val right = remoteById[id]
            val leftHash = left?.let { semanticHash(it) }
            val rightHash = right?.let { semanticHash(it) }
            val baseHash = baseMap[id]

            var chosen: Record? = null
            var copy: Record? = null
            when {
                leftHash == rightHash -> chosen = left ?: right
                leftHash == baseHash -> chosen = right
                rightHash == baseHash -> chosen = left
                else -> {
                    val resolution = resolve(left, right, vaultId)
                    chosen = resolution.winner
                    copy = resolution.copy
                    resolution.conflict?.let { conflicts.add(it) }
                }
            }
            chosen?.let {
                records.add(it)
                newBase[recordId(it)] = semanticHash(it)
            }
            copy?.let {
                records.add(it)
                newBase[recordId(it)] = semanticHash(it)
            }
        }
        return MergeResult(records, newBase, conflicts)
    }

    /** 历史按条目并集合并（只增不删）。 */
    fun mergeHistory(
        local: Map<String, List<Any?>>?,
        remote: Map<String, List<Any?>>?,
    ): Map<String, List<Any?>> {
        val left = local ?: emptyMap()
        val right = remote ?: emptyMap()
        val result = linkedMapOf<String, List<Any?>>()
        for (name in LinkedHashSet(left.keys + right.keys)) {
            val seen = mutableSetOf<String>()
            val entries = mutableListOf<Any?>()
            for (entry in (left[name] ?: emptyList()) + (right[name] ?: emptyList())) {
                val key = if (entry is List<*> || entry is Map<*, *>) Json.canonical(entry) else entry.toString()
                if (seen.add(key)) entries.add(entry)
            }
            entries.sortByDescending { entry ->
                if (entry is List<*> && entry.size > 2) entry[2] as? String ?: "" else ""
            }
            result[name] = entries
        }
        return result
    }
}
