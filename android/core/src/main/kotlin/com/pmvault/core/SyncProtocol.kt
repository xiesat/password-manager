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

    /** 发送已签名的请求，并校验响应签名；返回响应体。 */
    private fun request(method: String, path: String, body: ByteArray): ByteArray {
        val timestamp = System.currentTimeMillis().toString()
        val nonce = Crypto.hex(Crypto.randomBytes(16))
        val signature = SyncProtocol.signRequest(authKey, timestamp, nonce, method, path, body)

        val url = URL("http://" + pairing.host + ":" + pairing.port + path)
        val connection = (url.openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            if (body.isNotEmpty()) {
                doOutput = true
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
            }
            setRequestProperty("X-PM-Timestamp", timestamp)
            setRequestProperty("X-PM-Nonce", nonce)
            setRequestProperty("X-PM-Signature", signature)
        }

        return try {
            if (body.isNotEmpty()) connection.outputStream.use { it.write(body) }
            val code = connection.responseCode
            val stream = if (code in 200..299) connection.inputStream else connection.errorStream
            val responseBody = stream?.use { it.readBytes() } ?: ByteArray(0)

            if (code == 401) throw SyncException("认证失败：配对令牌不正确或已过期")
            if (code !in 200..299) {
                throw SyncException("主机返回错误 " + code + "：" + String(responseBody, Charsets.UTF_8))
            }
            if (!SyncProtocol.verifySignature(
                    authKey,
                    connection.getHeaderField("X-PM-Signature"),
                    connection.getHeaderField("X-PM-Timestamp") ?: "",
                    connection.getHeaderField("X-PM-Nonce") ?: "",
                    "RESPONSE",
                    path,
                    responseBody,
                )
            ) {
                throw SyncException("主机响应签名校验失败")
            }
            responseBody
        } catch (error: SyncException) {
            throw error
        } catch (error: Exception) {
            throw SyncException("同步失败：" + error.message)
        } finally {
            connection.disconnect()
        }
    }

    /** POST /sync：把本机密文发给主机，取回合并后的整库密文。 */
    fun sync(localBlob: String): String {
        val body = ("{\"vault\":" + Json.canonical(localBlob) + "}").toByteArray(Charsets.UTF_8)
        val json = JSONObject(String(request("POST", "/sync", body), Charsets.UTF_8))
        return json.optString("vault", "").ifEmpty { throw SyncException("主机返回内容为空") }
    }

    /** GET /vault：下载主机的整库密文（新设备"首次加入"用）。 */
    fun fetchVault(): String {
        val json = JSONObject(String(request("GET", "/vault", ByteArray(0)), Charsets.UTF_8))
        return json.optString("vault", "").ifEmpty { throw SyncException("主机返回内容为空") }
    }
}
