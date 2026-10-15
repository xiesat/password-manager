package com.pmvault.core

/**
 * 确定性密码生成器 v2（与 Python password_generator.py 逐字符一致）。
 *
 * 用 PBKDF2-HMAC-SHA256 派生密钥流 + 拒绝采样，盐由 SecureRandom 生成。
 */
object PasswordGenerator {

    const val ALGORITHM_V1 = "v1"
    const val ALGORITHM_V2 = "v2"
    const val SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    const val STREAM_ITERATIONS = 200_000
    const val DEFAULT_SALT_LENGTH = 16
    const val DEFAULT_LENGTH = 16
    const val DEFAULT_RULE_LENGTH = 16
    const val MIN_LENGTH = 4
    const val MAX_LENGTH = 128

    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private val secureRandom = java.security.SecureRandom()

    class Pool(val pool: String, val classes: List<String>)

    fun buildPool(lower: Boolean, upper: Boolean, digit: Boolean, symbol: Boolean): Pool {
        val classes = mutableListOf<String>()
        var pool = ""
        if (lower) { pool += LOWER; classes.add(LOWER) }
        if (upper) { pool += UPPER; classes.add(UPPER) }
        if (digit) { pool += DIGITS; classes.add(DIGITS) }
        if (symbol) { pool += SYMBOLS; classes.add(SYMBOLS) }
        if (pool.isEmpty()) {
            pool = LOWER + DIGITS
            classes.clear()
            classes.add(LOWER)
            classes.add(DIGITS)
        }
        return Pool(pool, classes)
    }

    fun randomSalt(length: Int = DEFAULT_SALT_LENGTH): String {
        val alphabet = LOWER + UPPER + DIGITS
        return buildString { repeat(length) { append(alphabet[secureRandom.nextInt(alphabet.length)]) } }
    }

    private class KeyStream(secret: String, salt: String) {
        private val secretBytes = secret.toByteArray(Charsets.UTF_8)
        private val saltBytes = salt.toByteArray(Charsets.UTF_8)
        private var block = 0
        private var buffer = ByteArray(0)

        private fun fill() {
            val material = saltBytes + "|".toByteArray(Charsets.UTF_8) +
                block.toString().toByteArray(Charsets.US_ASCII)
            buffer += Crypto.pbkdf2Sha256(secretBytes, material, STREAM_ITERATIONS, 32)
            block += 1
        }

        fun take(count: Int): ByteArray {
            while (buffer.size < count) fill()
            val out = buffer.copyOfRange(0, count)
            buffer = buffer.copyOfRange(count, buffer.size)
            return out
        }

        fun pick(pool: String): Char {
            val size = pool.length
            val limit = 256 - (256 % size)
            while (true) {
                val value = take(1)[0].toInt() and 0xFF
                if (value < limit) return pool[value % size]
            }
        }

        fun randBelow(n: Int): Int {
            if (n <= 1) return 0
            val bits = 32 - n.countLeadingZeroBits()
            val nbytes = (bits + 7) / 8
            var space = 1L
            repeat(nbytes) { space *= 256 }
            val limit = space - (space % n)
            while (true) {
                val bytes = take(nbytes)
                var value = 0L
                for (b in bytes) value = (value shl 8) or (b.toInt() and 0xFF).toLong()
                if (value < limit) return (value % n).toInt()
            }
        }

        fun shuffle(items: MutableList<Char>) {
            for (i in items.size - 1 downTo 1) {
                val j = randBelow(i + 1)
                val tmp = items[i]
                items[i] = items[j]
                items[j] = tmp
            }
        }
    }

    /** 生成 v2 密码；salt 为空时新建随机盐。返回 (密码, 实际使用的盐)。 */
    fun generateV2(
        inputText: String,
        length: Int,
        lower: Boolean = true,
        upper: Boolean = true,
        digit: Boolean = true,
        symbol: Boolean = true,
        salt: String? = null,
    ): Pair<String, String> {
        val usedSalt = salt ?: randomSalt()
        val pool = buildPool(lower, upper, digit, symbol)
        val stream = KeyStream(inputText, usedSalt)

        val parts = pool.classes.map { stream.pick(it) }.toMutableList()
        while (parts.size < length) parts.add(stream.pick(pool.pool))
        stream.shuffle(parts)
        return parts.joinToString("") to usedSalt
    }

    /**
     * 规则字符串：<len>|<lower>|<upper>|<digit>|<symbol>|<salt>|<algorithm>
     *
     * 布尔值必须写成 **True/False**（即 Python `str(bool)` 的形式）。
     * Kotlin 默认的 `true/false` 会让两端都解析成"四个字符类全 False"，
     * 于是历史密码被还原成另一个串 —— 表现就是"新密码和历史对不上"。
     */
    fun buildRule(
        length: Int, lower: Boolean, upper: Boolean, digit: Boolean, symbol: Boolean, salt: String,
    ): String = length.toString() + "|" + boolText(lower) + "|" + boolText(upper) + "|" +
        boolText(digit) + "|" + boolText(symbol) + "|" + salt + "|" + ALGORITHM_V2

    private fun boolText(value: Boolean): String = if (value) "True" else "False"

    /** 两种大小写都接受：旧版本 Android 写入的是 true/false。 */
    private fun boolValue(text: String): Boolean = text.equals("true", ignoreCase = true)

    /** 解析后的规则（与 Python model.parse_rule 等价）。 */
    data class RuleSpec(
        val length: Int,
        val lower: Boolean,
        val upper: Boolean,
        val digit: Boolean,
        val symbol: Boolean,
        val salt: String,
        val algorithm: String,
    )

    /**
     * 解析规则字符串，兼容 5 段（v1 无盐）、6 段（v1 带盐）、7 段（带算法）三种历史格式。
     * 无法识别时返回 null。
     */
    fun parseRule(rule: String): RuleSpec? {
        val parts = rule.split("|")
        val length: String
        val salt: String
        val algorithm: String
        when {
            parts.size == 5 -> {
                length = parts[0]
                salt = ""
                algorithm = ALGORITHM_V1
            }
            parts.size == 6 -> {
                length = parts[0]
                salt = parts[5]
                algorithm = ALGORITHM_V1
            }
            parts.size == 7 && (parts[6] == ALGORITHM_V1 || parts[6] == ALGORITHM_V2) -> {
                length = parts[0]
                salt = parts[5]
                algorithm = parts[6]
            }
            else -> return null
        }

        val lengthInt = length.toIntOrNull() ?: return null
        if (lengthInt < MIN_LENGTH || lengthInt > MAX_LENGTH) return null

        return RuleSpec(
            lengthInt,
            boolValue(parts[1]),
            boolValue(parts[2]),
            boolValue(parts[3]),
            boolValue(parts[4]),
            salt,
            algorithm,
        )
    }

    /** 默认规则（与桌面端 _default_rule 一致：16 位、四类字符全开、随机盐）。 */
    fun defaultRule(): String =
        buildRule(DEFAULT_RULE_LENGTH, true, true, true, true, randomSalt())

    /**
     * 按规则**确定性还原**密码（历史密码就是靠这个显示的）。
     * v1 规则或缺少盐的 v2 规则无法还原，返回 null。
     */
    fun regenerate(name: String, spec: RuleSpec): String? {
        if (spec.algorithm != ALGORITHM_V2) return null
        if (spec.salt.isEmpty()) return null
        return generateV2(
            name, spec.length, spec.lower, spec.upper, spec.digit, spec.symbol, spec.salt,
        ).first
    }

    /** 粗略强度评估，返回 0（空）或 1-5。 */
    fun estimateStrength(password: String): Int {
        if (password.isEmpty()) return 0
        val classes = listOf(
            password.any { it.isLowerCase() },
            password.any { it.isUpperCase() },
            password.any { it.isDigit() },
            password.any { !it.isLetterOrDigit() },
        ).count { it }
        val score = when {
            password.length < 8 -> 1
            password.length < 12 -> minOf(3, classes)
            else -> minOf(5, 1 + classes + (if (password.length >= 16) 1 else 0))
        }
        return score.coerceIn(1, 5)
    }
}
