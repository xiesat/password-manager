package com.pmvault.core

import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class VaultException(message: String) : Exception(message)

/**
 * v3 加密容器：AES-256-GCM + PBKDF2-HMAC-SHA256（迭代数写入文件头）。
 *
 *   v3:<base64( "PMGR" | version(1) | iterations(4) | salt(16) | nonce(12) | tag(16) | ciphertext )>
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

        fun decrypt(password: String, token: String): String {
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
            val ciphertextAndTag = blob.copyOfRange(offset, blob.size) + tag

            val key = Crypto.pbkdf2Sha256(password.toByteArray(Charsets.UTF_8), salt, iterations, KEY_SIZE)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
            cipher.updateAAD(blob.copyOfRange(0, HEADER_SIZE) + salt)
            return try {
                String(cipher.doFinal(ciphertextAndTag), Charsets.UTF_8)
            } catch (error: Exception) {
                throw VaultException("密钥不正确或文件已损坏")
            }
        }
    }

    fun encrypt(plaintext: String): String {
        val salt = Crypto.randomBytes(SALT_SIZE)
        val nonce = Crypto.randomBytes(NONCE_SIZE)
        val key = Crypto.pbkdf2Sha256(password.toByteArray(Charsets.UTF_8), salt, iterations, KEY_SIZE)

        val header = MAGIC_BYTES + byteArrayOf(FORMAT_VERSION.toByte()) + Crypto.intToBytes(iterations)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_SIZE * 8, nonce))
        cipher.updateAAD(header + salt)
        val ciphertextAndTag = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val split = ciphertextAndTag.size - TAG_SIZE
        val ciphertext = ciphertextAndTag.copyOfRange(0, split)
        val tag = ciphertextAndTag.copyOfRange(split, ciphertextAndTag.size)

        // Python 约定：tag 在 ciphertext 之前
        val blob = header + salt + nonce + tag + ciphertext
        return "v3:" + Base64.getEncoder().encodeToString(blob)
    }
}
