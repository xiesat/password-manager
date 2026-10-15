package com.pmvault.core

/** 混合逻辑时钟：<wall_ms:13>-<counter:04>-<device>，字典序即时间序。 */
object HlcFormat {
    const val WALL_DIGITS = 13
    const val COUNTER_DIGITS = 4
    const val MAX_COUNTER = 9999

    fun format(wallMs: Long, counter: Int, device: String): String =
        wallMs.toString().padStart(WALL_DIGITS, '0') + "-" +
            counter.toString().padStart(COUNTER_DIGITS, '0') + "-" + device

    fun parse(value: String): Triple<Long, Int, String> {
        val parts = value.split("-")
        require(
            parts.size == 3 && parts[2].isNotEmpty() &&
                parts[0].isNotEmpty() && parts[0].all { it.isDigit() } &&
                parts[1].isNotEmpty() && parts[1].all { it.isDigit() }
        ) { "非法的 HLC：$value" }
        return Triple(parts[0].toLong(), parts[1].toInt(), parts[2])
    }
}

class Hlc(private val device: String, initialWallMs: Long = 0) {

    private var wall: Long = initialWallMs
    private var counter: Int = 0

    init {
        require(device.isNotEmpty() && !device.contains('-')) { "device 不能为空且不能包含 '-'" }
    }

    /** 产生严格递增的时间戳；nowMs 可注入以便测试。 */
    @Synchronized
    fun next(nowMs: Long = System.currentTimeMillis()): String {
        if (nowMs > wall) {
            wall = nowMs
            counter = 0
        } else {
            counter += 1
            if (counter > HlcFormat.MAX_COUNTER) {
                wall += 1
                counter = 0
            }
        }
        return HlcFormat.format(wall, counter, device)
    }

    /** 吸收对端时间戳。 */
    @Synchronized
    fun observe(value: String?) {
        if (value.isNullOrEmpty()) return
        val parsed = runCatching { HlcFormat.parse(value) }.getOrNull() ?: return
        val (remoteWall, remoteCounter, _) = parsed
        if (remoteWall > wall || (remoteWall == wall && remoteCounter > counter)) {
            wall = remoteWall
            counter = remoteCounter
        }
    }
}
