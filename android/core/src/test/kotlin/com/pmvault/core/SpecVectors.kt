package com.pmvault.core

import java.io.File
import org.json.JSONObject

private var failures = 0
private var checks = 0

private fun check(name: String, condition: Boolean, detail: String = "") {
    checks += 1
    if (condition) {
        println("  ok   " + name)
    } else {
        failures += 1
        println("  FAIL " + name + if (detail.isEmpty()) "" else "  (" + detail + ")")
    }
}

private fun stringList(array: org.json.JSONArray): List<String> =
    (0 until array.length()).map { array.get(it).toString() }

fun main(args: Array<String>) {
    val root = if (args.isNotEmpty()) args[0] else "."

    println("== 1. HKDF-SHA256 (RFC 5869 test case 1) ==")
    run {
        val ikm = Crypto.fromHex("0b".repeat(22))
        val salt = Crypto.fromHex("000102030405060708090a0b0c")
        val info = Crypto.fromHex("f0f1f2f3f4f5f6f7f8f9")
        val expected = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        check("okm matches", Crypto.hex(Crypto.hkdfSha256(ikm, salt, info, 42)) == expected)
    }

    val vectors = JSONObject(File(root, "spec/merge_vectors.json").readText(Charsets.UTF_8))

    println("== 2. 规范化 JSON / 语义哈希 ==")
    run {
        val list = vectors.getJSONArray("hash_vectors")
        for (index in 0 until list.length()) {
            val entry = list.getJSONObject(index)
            val record = JsonValues.toRecord(entry.getJSONObject("record"))
            val payload = Merge.semanticPayload(record)
            check("canonical#" + index, Json.canonical(payload) == entry.getString("canonical"), Json.canonical(payload))
            check("semanticHash#" + index, Merge.semanticHash(record) == entry.getString("semantic_hash"))
        }
    }

    println("== 3. 三方合并（黄金向量） ==")
    run {
        val cases = vectors.getJSONArray("cases")
        for (index in 0 until cases.length()) {
            val case = cases.getJSONObject(index)
            val name = case.getString("name")
            val vaultId = case.getString("vault_id")

            val base = linkedMapOf<String, String>()
            val baseJson = case.getJSONObject("base")
            for (key in baseJson.keys()) base[key] = baseJson.getString(key)

            val local = JsonValues.toRecordList(case.getJSONArray("local"))
            val remote = JsonValues.toRecordList(case.getJSONArray("remote"))
            val expected = case.getJSONObject("expected")

            val result = Merge.mergeRecords(base, local, remote, vaultId)
            val ids = result.records.map { Merge.recordId(it) }.sorted()
            val alive = result.records.filter { !Merge.isDeleted(it) }
                .map { it["password"] as? String ?: "" }.sorted()
            val deleted = result.records.filter { Merge.isDeleted(it) }.map { Merge.recordId(it) }.sorted()

            val expectedBase = linkedMapOf<String, String>()
            val expectedBaseJson = expected.getJSONObject("base")
            for (key in expectedBaseJson.keys()) expectedBase[key] = expectedBaseJson.getString(key)

            val copyIds = result.conflicts.map { it.copyId }
            val expectedCopyIds: List<String?> = (0 until expected.getJSONArray("conflict_copy_ids").length())
                .map { i ->
                    val value = expected.getJSONArray("conflict_copy_ids").get(i)
                    if (value == JSONObject.NULL) null else value.toString()
                }

            check(name + " recordIds", ids == stringList(expected.getJSONArray("record_ids")).sorted())
            check(name + " alivePasswords", alive == stringList(expected.getJSONArray("alive_passwords")).sorted())
            check(name + " deletedIds", deleted == stringList(expected.getJSONArray("deleted_ids")).sorted())
            check(name + " conflictKinds", result.conflicts.map { it.kind } == stringList(expected.getJSONArray("conflict_kinds")))
            check(name + " conflictCopyIds", copyIds == expectedCopyIds)
            check(name + " base", result.base == expectedBase)
            check(name + " contentHash", result.contentHash == expected.getString("content_hash"))

            val swapped = Merge.mergeRecords(base, remote, local, vaultId)
            check(name + " commutative", swapped.contentHash == result.contentHash)
        }
    }

    println("== 4. 跨语言加解密（Python 生成 → Kotlin 解密） ==")
    run {
        val key = File(root, "spec/fixtures/cross_language.key").readText(Charsets.UTF_8)
        val token = File(root, "spec/fixtures/cross_language.sk").readText(Charsets.UTF_8).trim()
        val expected = File(root, "spec/fixtures/cross_language.expected.json").readText(Charsets.UTF_8)
        val decrypted = VaultCipher.decrypt(key, token)
        check("decrypt python vault", decrypted == expected, "len=" + decrypted.length + "/" + expected.length)
        val payload = VaultPayload.parse(decrypted)
        check("schema", payload.schema == 4)
        check("record name", payload.mainData.first()["name"] == "跨语言测试🔐")
        check("record password", payload.mainData.first()["password"] == "P@ssw0rd-测试-!@#")
    }
    run {
        val token = VaultCipher("k", iterations = 1234).encrypt("hello 世界 🔐")
        check("roundtrip", VaultCipher.decrypt("k", token) == "hello 世界 🔐")
        val blob = java.util.Base64.getDecoder().decode(token.substring(3))
        check("header version", blob[4].toInt() == 3)
        check("header iterations", Crypto.bytesToInt(blob, 5) == 1234)
    }
    run {
        // 复用同一个 VaultKey 连续保存：不重跑 PBKDF2，但每次必须是新 nonce
        val material = VaultKey.create("k", iterations = 1234)
        val first = material.encrypt("同一段明文")
        val second = material.encrypt("同一段明文")
        check("reused key -> different nonce", first != second)
        check("reused key decrypts first", VaultCipher.decrypt("k", first) == "同一段明文")
        check("reused key decrypts second", VaultCipher.decrypt("k", second) == "同一段明文")
        check("reused key keeps salt", VaultCipher.parse(first).salt.contentEquals(material.salt))
        check("reused key keeps iterations", VaultCipher.parse(first).iterations == 1234)
    }
    run {
        // 用 VaultKey 打开 Python 生成的库，再用解出的密钥重新加密：结构必须仍与 Python 兼容
        val fixtureKey = File(root, "spec/fixtures/cross_language.key").readText(Charsets.UTF_8)
        val fixtureToken = File(root, "spec/fixtures/cross_language.sk").readText(Charsets.UTF_8).trim()
        val fixtureExpected = File(root, "spec/fixtures/cross_language.expected.json").readText(Charsets.UTF_8)
        val (material, plaintext) = VaultKey.unlock(fixtureKey, fixtureToken)
        check("unlock() reads fixture", plaintext == fixtureExpected)
        check("unlock() keeps iterations", material.iterations == VaultCipher.parse(fixtureToken).iterations)
        val reEncrypted = material.encrypt(plaintext)
        val (again, roundTrip) = VaultKey.unlock(fixtureKey, reEncrypted)
        check("re-encrypt with reused key", roundTrip == fixtureExpected)
        check("re-encrypt keeps salt", again.salt.contentEquals(material.salt))
    }
    run {
        // 手机端生成的夹具（会话内复用盐保存两次）也要能读回
        val fixtureKey = File(root, "spec/fixtures/reused_key.key").readText(Charsets.UTF_8)
        val blob = File(root, "spec/fixtures/reused_key.sk").readText(Charsets.UTF_8).trim()
        val expected = File(root, "spec/fixtures/reused_key.expected.json").readText(Charsets.UTF_8)
        val (_, plaintext) = VaultKey.unlock(fixtureKey, blob)
        check("kotlin fixture opens", plaintext == expected)

        val first = VaultCipher.parse(
            File(root, "spec/fixtures/reused_key.first.sk").readText(Charsets.UTF_8).trim()
        )
        val second = VaultCipher.parse(blob)
        check("kotlin fixture reuses salt", first.salt.contentEquals(second.salt))
        check("kotlin fixture fresh nonce", !first.nonce.contentEquals(second.nonce))
        check("kotlin fixture iterations", second.iterations == 200_000)
    }

    println("== 5. HLC ==")
    run {
        val hlc = Hlc("dev00001", initialWallMs = 1000)
        val first = hlc.next(1000)
        val second = hlc.next(1000)
        check("fixed width", first.length == second.length)
        check("strictly increasing", first < second)
        check("counter increments", HlcFormat.parse(second).second == HlcFormat.parse(first).second + 1)
        val remote = HlcFormat.format(5000, 7, "dev00002")
        hlc.observe(remote)
        check("observe advances", hlc.next(1000) > remote)
    }

    println("== 6. 同步协议签名 ==")
    run {
        val authKey = SyncProtocol.deriveAuthKey("tok", "vid")
        val body = "{\"vault\":\"x\"}".toByteArray(Charsets.UTF_8)
        val signature = SyncProtocol.signRequest(authKey, "1", "n".repeat(16), "POST", "/sync", body)
        check("verify ok", SyncProtocol.verifySignature(authKey, signature, "1", "n".repeat(16), "POST", "/sync", body))
        check("tamper body rejected", !SyncProtocol.verifySignature(authKey, signature, "1", "n".repeat(16), "POST", "/sync", "{\"vault\":\"y\"}".toByteArray(Charsets.UTF_8)))
        check("tamper path rejected", !SyncProtocol.verifySignature(authKey, signature, "1", "n".repeat(16), "POST", "/other", body))
    }

    println("== 7. 确定性密码生成器（跨语言） ==")
    run {
        val generatorVectors = JSONObject(File(root, "spec/generator_vectors.json").readText(Charsets.UTF_8))
        val list = generatorVectors.getJSONArray("vectors")
        for (index in 0 until list.length()) {
            val entry = list.getJSONObject(index)
            val generated = PasswordGenerator.generateV2(
                entry.getString("input_text"),
                entry.getInt("length"),
                entry.getBoolean("lower"),
                entry.getBoolean("upper"),
                entry.getBoolean("digit"),
                entry.getBoolean("symbol"),
                entry.getString("salt"),
            )
            check(
                "generator#" + index,
                generated.first == entry.getString("password") && generated.second == entry.getString("salt"),
                generated.first,
            )
        }
        val sample = PasswordGenerator.generateV2("Google", 12, salt = "AbC123xyz")
        check("generator deterministic", sample.first == PasswordGenerator.generateV2("Google", 12, salt = "AbC123xyz").first)
        check("generator random salt", PasswordGenerator.randomSalt(16).length == 16)
    }

    println("== 8. 同步协议签名（跨语言） ==")
    run {
        val syncVectors = JSONObject(File(root, "spec/sync_vectors.json").readText(Charsets.UTF_8))
        val authKey = SyncProtocol.deriveAuthKey(
            syncVectors.getString("token"),
            syncVectors.getString("vault_id"),
        )
        check("authKey matches", Crypto.hex(authKey) == syncVectors.getString("auth_key_hex"))

        val list = syncVectors.getJSONArray("signatures")
        for (index in 0 until list.length()) {
            val entry = list.getJSONObject(index)
            val body = entry.getString("body").toByteArray(Charsets.UTF_8)
            val signature = SyncProtocol.signRequest(
                authKey,
                entry.getString("timestamp"),
                entry.getString("nonce"),
                entry.getString("method"),
                entry.getString("path"),
                body,
            )
            check("signature#" + index, signature == entry.getString("signature"), signature)
            check(
                "verify#" + index,
                SyncProtocol.verifySignature(
                    authKey, signature,
                    entry.getString("timestamp"), entry.getString("nonce"),
                    entry.getString("method"), entry.getString("path"), body,
                ),
            )
        }
    }

    println("== 9. 规则解析与历史密码还原（跨语言） ==")
    run {
        val vectors = JSONObject(File(root, "spec/generator_vectors.json").readText(Charsets.UTF_8))

        val rules = vectors.getJSONArray("rule_vectors")
        for (index in 0 until rules.length()) {
            val entry = rules.getJSONObject(index)
            val spec = PasswordGenerator.parseRule(entry.getString("rule"))
            if (!entry.getBoolean("valid")) {
                check("rule#" + index + " rejected", spec == null, entry.getString("rule"))
            } else {
                val matches = spec != null &&
                    spec.length == entry.getInt("length") &&
                    spec.lower == entry.getBoolean("lower") &&
                    spec.upper == entry.getBoolean("upper") &&
                    spec.digit == entry.getBoolean("digit") &&
                    spec.symbol == entry.getBoolean("symbol") &&
                    spec.salt == entry.getString("salt") &&
                    spec.algorithm == entry.getString("algorithm")
                check("rule#" + index, matches, entry.getString("rule"))
            }
        }

        val regenerate = vectors.getJSONArray("regenerate_vectors")
        for (index in 0 until regenerate.length()) {
            val entry = regenerate.getJSONObject(index)
            val spec = PasswordGenerator.parseRule(entry.getString("rule"))
            val actual = if (spec == null) {
                null
            } else {
                PasswordGenerator.regenerate(entry.getString("name"), spec)
            }
            check("regenerate#" + index, actual == entry.getString("password"), actual ?: "null")
        }
    }

    println("checks=" + checks + " failures=" + failures)
    println(if (failures == 0) "ALL KOTLIN CORE CHECKS PASSED" else "FAILURES: " + failures)
    if (failures > 0) kotlin.system.exitProcess(1)
}
