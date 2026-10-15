package com.pmvault.core

import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** 哈希 / HMAC / HKDF / UUIDv5 等基础原语。全部与 Python 参考实现逐字节一致。 */
object Crypto {

    private val random = java.security.SecureRandom()

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { random.nextBytes(it) }

    fun intToBytes(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(), (value ushr 16).toByte(),
        (value ushr 8).toByte(), value.toByte(),
    )

    fun bytesToInt(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)

    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun sha256Hex(text: String): String = hex(sha256(text.toByteArray(Charsets.UTF_8)))

    fun hex(bytes: ByteArray): String = buildString(bytes.size * 2) {
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            append(HEX[v ushr 4])
            append(HEX[v and 0x0F])
        }
    }

    fun fromHex(text: String): ByteArray {
        require(text.length % 2 == 0) { "hex 长度必须是偶数" }
        return ByteArray(text.length / 2) { i ->
            ((Character.digit(text[i * 2], 16) shl 4) or Character.digit(text[i * 2 + 1], 16)).toByte()
        }
    }

    fun hmacSha256(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }

    /**
     * PBKDF2-HMAC-SHA256（RFC 2898）。
     * 手写实现而非用 SecretKeyFactory，确保与 Python hashlib.pbkdf2_hmac 对
     * 非 ASCII 口令的字节处理完全一致。
     */
    fun pbkdf2Sha256(password: ByteArray, salt: ByteArray, iterations: Int, length: Int): ByteArray {
        val out = ByteArray(length)
        val blocks = (length + 31) / 32
        // 整次派生只建一个 Mac 并复用：Mac.doFinal 完成后会自动 reset 回 init 状态，
        // 与每轮新建 Mac 的结果完全一致，但省掉了 iterations 次 provider 查找与对象分配。
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(password, "HmacSHA256"))
        var offset = 0
        for (block in 1..blocks) {
            val blockIndex = byteArrayOf(
                (block ushr 24).toByte(), (block ushr 16).toByte(),
                (block ushr 8).toByte(), block.toByte(),
            )
            var u = mac.doFinal(salt + blockIndex)
            val acc = u.copyOf()
            for (i in 2..iterations) {
                u = mac.doFinal(u)
                for (j in acc.indices) acc[j] = (acc[j].toInt() xor u[j].toInt()).toByte()
            }
            val take = minOf(32, length - offset)
            System.arraycopy(acc, 0, out, offset, take)
            offset += take
        }
        return out
    }

    /** RFC 5869 HKDF-SHA256。 */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        val effectiveSalt = if (salt.isNotEmpty()) salt else ByteArray(32)
        val prk = hmacSha256(effectiveSalt, ikm)
        val okm = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            previous = hmacSha256(prk, previous + info + byteArrayOf(counter.toByte()))
            val take = minOf(previous.size, length - offset)
            System.arraycopy(previous, 0, okm, offset, take)
            offset += take
            counter += 1
        }
        return okm
    }

    /** RFC 4122 UUIDv5（与 Python uuid.uuid5 输出一致）。 */
    fun uuid5(namespace: UUID, name: String): UUID {
        val digest = MessageDigest.getInstance("SHA-1")
        val ns = java.nio.ByteBuffer.allocate(16)
            .putLong(namespace.mostSignificantBits)
            .putLong(namespace.leastSignificantBits)
            .array()
        digest.update(ns)
        digest.update(name.toByteArray(Charsets.UTF_8))
        val hash = digest.digest()
        hash[6] = ((hash[6].toInt() and 0x0F) or 0x50).toByte()
        hash[8] = ((hash[8].toInt() and 0x3F) or 0x80).toByte()
        val buffer = java.nio.ByteBuffer.wrap(hash)
        return UUID(buffer.long, buffer.long)
    }

    fun constantTimeEquals(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

    private val HEX = "0123456789abcdef".toCharArray()
}
