package com.pmvault.core

/**
 * 规范化 JSON 序列化：键排序、无空白、非 ASCII 原样输出。
 * 必须与 Python json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")) 逐字节一致。
 */
object Json {

    fun canonical(value: Any?): String = buildString { write(this, value) }

    private fun write(sb: StringBuilder, value: Any?) {
        when (value) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (value) "true" else "false")
            is String -> writeString(sb, value)
            is Int -> sb.append(value.toString())
            is Long -> sb.append(value.toString())
            is Map<*, *> -> {
                sb.append('{')
                val keys = value.keys.map { it.toString() }.sorted()
                keys.forEachIndexed { index, key ->
                    if (index > 0) sb.append(',')
                    writeString(sb, key)
                    sb.append(':')
                    write(sb, value[key])
                }
                sb.append('}')
            }
            is List<*> -> {
                sb.append('[')
                value.forEachIndexed { index, item ->
                    if (index > 0) sb.append(',')
                    write(sb, item)
                }
                sb.append(']')
            }
            else -> writeString(sb, value.toString())
        }
    }

    private fun writeString(sb: StringBuilder, text: String) {
        sb.append('"')
        for (ch in text) {
            when (ch) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                else -> if (ch < ' ') {
                    sb.append("\\u")
                    sb.append(ch.code.toString(16).padStart(4, '0'))
                } else {
                    sb.append(ch)
                }
            }
        }
        sb.append('"')
    }
}
