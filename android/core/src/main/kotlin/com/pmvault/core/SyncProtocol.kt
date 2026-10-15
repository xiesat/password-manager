package com.pmvault.core

import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

class SyncException(message: String) : Exception(message)

/** 局域网同步协议（见 spec/SYNC_PROTOCOL.md）。 */
object SyncProtocol {
    const val PROTOCOL_VERSION = 1
    const val REPLAY_WINDOW_MS = 120_000L
    const val NONCE_MIN_LENGTH = 16
    const val AUTH_INFO = "pm-sync-auth-v1"

    fun deriveAuthKey(token: String, vaultId: String): ByteArray = Crypto.hkdfSha256(
        token.toByteArray(Charsets.UTF_8),
        vaultId.toByteArray(Charsets.UTF_8),
        AUTH_INFO.toByteArray(Charsets.UTF_8),
        32,
    )

    private fun signatureMessage(
        timestamp: String, nonce: String, method: String, path: String, body: ByteArray,
    ): ByteArray {
        val digest = Crypto.hex(Crypto.sha256(body))
        val message = timestamp + "\n" + nonce + "\n" + method.uppercase() + "\n" + path + "\n" + digest
        return message.toByteArray(Charsets.UTF_8)
    }

    fun signRequest(
        authKey: ByteArray, timestamp: String, nonce: String, method: String, path: String, body: ByteArray,
    ): String = Crypto.hex(Crypto.hmacSha256(authKey, signatureMessage(timestamp, nonce, method, path, body)))

    fun verifySignature(
        authKey: ByteArray, signature: String?, timestamp: String, nonce: String,
        method: String, path: String, body: ByteArray,
    ): Boolean {
        val expected = signRequest(authKey, timestamp, nonce, method, path, body)
        return signature != null && Crypto.constantTimeEquals(expected, signature)
    }
}

data class PairingInfo(
    val host: String,
    val port: Int,
    val token: String,
    val vaultId: String,
    val deviceId: String,
    val deviceName: String,
) {
    companion object {
        fun parse(text: String): PairingInfo {
            val obj = try {
                JSONObject(text)
            } catch (error: Exception) {
                throw SyncException("配对信息格式错误（应为 JSON）")
            }
            val host = obj.optString("host", "")
            val port = obj.optInt("port", 0)
            val token = obj.optString("token", "")
            val vaultId = obj.optString("vault_id", "")
            if (host.isEmpty() || port <= 0 || token.isEmpty() || vaultId.isEmpty()) {
                throw SyncException("配对信息缺少必要字段（host/port/token/vault_id）")
            }
            return PairingInfo(
                host, port, token, vaultId,
                obj.optString("device_id", ""), obj.optString("device_name", ""),
            )
        }
    }
}

/** 客户端：把本机密文发给主机，取回合并后的整库密文。 */
class SyncClient(private val pairing: PairingInfo, private val timeoutMs: Int = 15_000) {

    private val authKey: ByteArray = SyncProtocol.deriveAuthKey(pairing.token, pairing.vaultId)

    fun sync(localBlob: String): String {
        val body = ("{\"vault\":" + Json.canonical(localBlob) + "}").toByteArray(Charsets.UTF_8)
        val timestamp = System.currentTimeMillis().toString()
        val nonce = Crypto.hex(Crypto.randomBytes(16))
        val signature = SyncProtocol.signRequest(authKey, timestamp, nonce, "POST", "/sync", body)

        val url = URL("http://" + pairing.host + ":" + pairing.port + "/sync")
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            doOutput = true
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("X-PM-Timestamp", timestamp)
            setRequestProperty("X-PM-Nonce", nonce)
            setRequestProperty("X-PM-Signature", signature)
        }

        return try {
            connection.outputStream.use { it.write(body) }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val responseBody = stream?.use { it.readBytes() } ?: ByteArray(0)
            if (code == 401) throw SyncException("认证失败：配对令牌不正确或已过期")
            if (code !in 200..299) throw SyncException("主机返回错误 " + code + "：" + String(responseBody, Charsets.UTF_8))

            val responseSignature = connection.getHeaderField("X-PM-Signature")
            val responseTimestamp = connection.getHeaderField("X-PM-Timestamp") ?: ""
            val responseNonce = connection.getHeaderField("X-PM-Nonce") ?: ""
            if (!SyncProtocol.verifySignature(
                    authKey, responseSignature, responseTimestamp, responseNonce,
                    "RESPONSE", "/sync", responseBody,
                )
            ) {
                throw SyncException("主机响应签名校验失败")
            }

            val json = JSONObject(String(responseBody, Charsets.UTF_8))
            json.optString("vault", "").ifEmpty { throw SyncException("主机返回内容为空") }
        } catch (error: SyncException) {
            throw error
        } catch (error: Exception) {
            throw SyncException("同步失败：" + error.message)
        } finally {
            connection.disconnect()
        }
    }
}
