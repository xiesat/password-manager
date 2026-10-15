package com.pmvault.core

import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class VaultException(message: String) : Exception(message)

/** v3 容器的结构（已解析、未解密）。 */
class VaultParts(
    val iterations: Int,
    val salt: ByteArray,
    val nonce: ByteArray,
    val tag: ByteArray,
    val ciphertext: ByteArray,
    /** AES-GCM 的附加认证数据（文件头 + 盐）。 */
    val aad: ByteArray,
)

/**
 * v3 加密容器：AES-256-GCM + PBKDF2-HMAC-SHA256（迭代数写入文件头）。
 *
 *   v3:<base64( "PMGR" | version(1) | iterations(4) | salt(16) | nonce(12) | tag(16) | ciphertext )>
 *
 * 注意：[encrypt] 每次都会**新建随机盐**，因此必然包含一次 60 万次 PBKDF2。
 * 会话内连续保存请用 [VaultKey]，它复用已派生的密钥与盐。
 */
class VaultCipher(
    private val password: String,
    val iterations: Int = DEFAULT_ITERATIONS,
) {

    companion object {
        const val FORMAT_VERSION = 3
        const val DEFAULT_ITERATIONS = 600_000
        const val SALT_SIZE = 16
        const val NONCE_SIZE = 12
        const val TAG_SIZE = 16
        const val KEY_SIZE = 32
        const val MAGIC = "PMGR"
        const val HEADER_SIZE = 4 + 1 + 4
        private val MAGIC_BYTES = MAGIC.toByteArray(Charsets.US_ASCII)

        fun detectFormat(content: String): Int = when {
            content.startsWith("v3:") -> 3
            content.startsWith("v2:") -> 2
            else -> 1
        }

        internal fun buildHeader(iterations: Int): ByteArray =
            MAGIC_BYTES + byteArrayOf(FORMAT_VERSION.toByte()) + Crypto.intToBytes(iterations)

        /** 解析 v3 密文结构（不解密）。 */
        fun parse(token: String): VaultParts {
            val raw = if (token.startsWith("v3:")) token.substring(3) else token
            val blob = try {
                Base64.getDecoder().decode(raw)
            } catch (error: IllegalArgumentException) {
                throw VaultException("文件内容不是合法的 Base64")
            }
            if (blob.size < HEADER_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE) {
                throw VaultException("文件长度异常")
            }
            if (!blob.copyOfRange(0, 4).contentEquals(MAGIC_BYTES)) {
                throw VaultException("文件标识不匹配，可能不是本程序生成")
            }
            if (blob[4].toInt() != FORMAT_VERSION) {
                throw VaultException("不支持的格式版本：" + blob[4].toInt())
            }
            val iterations = Crypto.bytesToInt(blob, 5)

            var offset = HEADER_SIZE
            val salt = blob.copyOfRange(offset, offset + SALT_SIZE)
            offset += SALT_SIZE
            val nonce = blob.copyOfRange(offset, offset + NONCE_SIZE)
            offset += NONCE_SIZE
            // 磁盘布局是 tag || ciphertext（与 Python 参考实现一致），
            // 而 JCE 的 GCM 需要 ciphertext || tag，这里重新拼接。
            val tag = blob.copyOfRange(offset, offset + TAG_SIZE)
            offset += TAG_SIZE
            val ciphertext = blob.copyOfRange(offset, blob.size)

            return VaultParts(
                iterations = iterations,
                salt = salt,
                nonce = nonce,
                tag = tag,
                ciphertext = ciphertext,
                aad = blob.copyOfRange(0, HEADER_SIZE) + salt,
            )
        }

        fun decrypt(password: String, token: String): String {
            val parts = parse(token)
            val key = Crypto.pbkdf2Sha256(
                password.toByteArray(Charsets.UTF_8), parts.salt, parts.iterations, KEY_SIZE,
            )
            return VaultKey(key, parts.salt, parts.iterations).decrypt(parts)
        }
    }

    fun encrypt(plaintext: String): String =
        VaultKey.create(password, iterations).encrypt(plaintext)
}

/**
 * 已派生的库密钥（含 PBKDF2 的盐与迭代数），可在一次会话内反复复用。
 *
 * 复用它之后，保存时只需要一次 AES-GCM，**不再重跑 60 万次 PBKDF2** ——
 * 这是手机端最主要的耗时来源。
 * 每次加密都生成**新的随机 nonce**：GCM 下同一密钥绝不能重复使用 nonce。
 */
class VaultKey(
    val key: ByteArray,
    val salt: ByteArray,
    val iterations: Int,
) {

    /** 用本密钥加密（只做 AES-GCM，不含 PBKDF2）。 */
    fun encrypt(plaintext: String): String {
        val nonce = Crypto.randomBytes(VaultCipher.NONCE_SIZE)
        val header = VaultCipher.buildHeader(iterations)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(VaultCipher.TAG_SIZE * 8, nonce),
        )
        cipher.updateAAD(header + salt)
        val ciphertextAndTag = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val split = ciphertextAndTag.size - VaultCipher.TAG_SIZE
        val ciphertext = ciphertextAndTag.copyOfRange(0, split)
        val tag = ciphertextAndTag.copyOfRange(split, ciphertextAndTag.size)

        // Python 约定：tag 在 ciphertext 之前
        val blob = header + salt + nonce + tag + ciphertext
        return "v3:" + Base64.getEncoder().encodeToString(blob)
    }

    internal fun decrypt(parts: VaultParts): String {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(VaultCipher.TAG_SIZE * 8, parts.nonce),
        )
        cipher.updateAAD(parts.aad)
        return try {
            String(cipher.doFinal(parts.ciphertext + parts.tag), Charsets.UTF_8)
        } catch (error: Exception) {
            throw VaultException("密钥不正确或文件已损坏")
        }
    }

    companion object {
        /** 新建库：随机盐 + 一次 PBKDF2。 */
        fun create(password: String, iterations: Int = VaultCipher.DEFAULT_ITERATIONS): VaultKey {
            val salt = Crypto.randomBytes(VaultCipher.SALT_SIZE)
            val key = Crypto.pbkdf2Sha256(
                password.toByteArray(Charsets.UTF_8), salt, iterations, VaultCipher.KEY_SIZE,
            )
            return VaultKey(key, salt, iterations)
        }

        /** 打开已有库：按文件头里的盐与迭代数派生一次，返回可复用的密钥与明文。 */
        fun unlock(password: String, token: String): Pair<VaultKey, String> {
            val parts = VaultCipher.parse(token)
            val key = Crypto.pbkdf2Sha256(
                password.toByteArray(Charsets.UTF_8), parts.salt, parts.iterations, VaultCipher.KEY_SIZE,
            )
            val material = VaultKey(key, parts.salt, parts.iterations)
            return material to material.decrypt(parts)
        }
    }
}
