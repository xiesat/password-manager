package com.pmvault.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.initializer
import androidx.lifecycle.viewmodel.viewModelFactory
import com.pmvault.core.Record
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class VaultViewModel(private val repository: VaultRepository) : ViewModel() {

    var locked by mutableStateOf(true)
        private set
    var hasVault by mutableStateOf(repository.exists())
        private set
    var records by mutableStateOf<List<Record>>(emptyList())
        private set
    var status by mutableStateOf("")
        private set
    var busy by mutableStateOf(false)
        private set

    /** 当前正在做什么。耗时操作都在 IO 线程，靠它告诉用户"是在算，不是卡住"。 */
    var busyMessage by mutableStateOf("")
        private set

    var historyEntries by mutableStateOf<List<VaultRepository.HistoryEntry>>(emptyList())
        private set
    var historyLoading by mutableStateOf(false)
        private set
    var historyDone by mutableStateOf(0)
        private set
    var historyTotal by mutableStateOf(0)
        private set

    /** 上次用过的配对信息：反复同步时不必每次重新扫码。 */
    var pairingText by mutableStateOf("")
        private set

    fun updatePairingText(value: String) {
        pairingText = value
    }

    private var historyJob: Job? = null

    // 历史密码缓存：同一条记录 + 库版本没变时直接复用，避免每次打开都重算 20 万次 PBKDF2
    private var cachedHistoryName: String? = null
    private var cachedHistoryRev: Long = -1L
    private var cachedHistory: List<VaultRepository.HistoryEntry> = emptyList()

    val vaultId: String? get() = repository.state?.vaultId
    val deviceId: String get() = repository.deviceId

    private fun refresh() {
        // 拷贝成新的 Map 实例：原地修改会让新旧列表结构相等，Compose 就检测不到变化
        records = (repository.state?.records ?: emptyList()).map { LinkedHashMap(it) }
        hasVault = repository.exists()
    }

    private fun launchAction(message: String, block: suspend () -> String) {
        if (busy) return  // viewModelScope 跑在 Main.immediate，busy 会被同步置位，可挡住连点
        viewModelScope.launch {
            busy = true
            busyMessage = message
            try {
                status = withContext(Dispatchers.IO) { block() }
                refresh()
            } catch (error: Exception) {
                status = "失败：" + (error.message ?: error.javaClass.simpleName)
            } finally {
                busy = false
                busyMessage = ""
            }
        }
    }

    fun createVault(password: String) {
        if (password.length < 6) {
            status = "密钥至少 6 位"
            return
        }
        launchAction("正在创建密码库（PBKDF2 60 万次）…") {
            repository.create(password)
            locked = false
            "已创建新的密码库"
        }
    }

    fun unlock(password: String) {
        if (password.isEmpty()) {
            status = "请输入密钥"
            return
        }
        launchAction("正在解锁（PBKDF2 60 万次）…") {
            repository.unlock(password)
            locked = false
            "解锁成功"
        }
    }

    fun lock() {
        clearHistory()
        repository.lock()
        locked = true
        records = emptyList()
        status = "已锁定"
    }

    fun addEntry(
        name: String,
        length: Int,
        lower: Boolean,
        upper: Boolean,
        digit: Boolean,
        symbol: Boolean,
    ) {
        if (name.isBlank()) {
            status = "名称不能为空"
            return
        }
        launchAction("正在生成密码并保存…") {
            repository.addEntry(name.trim(), length, lower, upper, digit, symbol)
            "已添加并生成密码"
        }
    }

    /** 重新生成某条记录的密码（次数 +1，旧密码进入历史）。 */
    fun regenerate(index: Int) {
        launchAction("正在重新生成密码并保存（PBKDF2 80 万次）…") {
            repository.regenerate(index)
            "已重新生成密码"
        }
    }

    fun delete(index: Int) {
        launchAction("正在保存…") {
            repository.deleteEntries(listOf(index))
            "已删除"
        }
    }

    /**
     * 逐条还原历史密码。
     * 每条历史都要跑一次 20 万次 PBKDF2，所以必须离开主线程，并逐条汇报进度。
     */
    fun loadHistory(name: String) {
        val revision = repository.revision()

        // 命中缓存：库没改过就直接用上次算好的结果
        if (cachedHistoryName == name && cachedHistoryRev == revision) {
            historyJob?.cancel()
            historyJob = null
            historyEntries = cachedHistory
            historyTotal = cachedHistory.size
            historyDone = cachedHistory.size
            historyLoading = false
            return
        }

        historyJob?.cancel()
        val rows = repository.rawHistory(name)
        historyEntries = emptyList()
        historyTotal = rows.size
        historyDone = 0
        if (rows.isEmpty()) {
            cachedHistoryName = name
            cachedHistoryRev = revision
            cachedHistory = emptyList()
            historyLoading = false
            return
        }

        historyLoading = true
        historyJob = viewModelScope.launch {
            val collected = mutableListOf<VaultRepository.HistoryEntry>()
            for ((position, row) in rows.withIndex()) {
                val entry = withContext(Dispatchers.Default) {
                    repository.deriveHistoryEntry(name, row)
                }
                if (entry != null) collected.add(entry)
                historyEntries = collected.toList()
                historyDone = position + 1
            }
            cachedHistoryName = name
            cachedHistoryRev = revision
            cachedHistory = collected.toList()
            historyLoading = false
        }
    }

    fun clearHistory() {
        historyJob?.cancel()
        historyJob = null
        historyLoading = false
        historyEntries = emptyList()
        historyDone = 0
        historyTotal = 0
    }

    /** 从桌面端导入整个密码库（新手机首次使用）。 */
    fun importFromHost(pairingText: String, password: String) {
        if (pairingText.isBlank()) {
            status = "请先扫描或粘贴配对信息"
            return
        }
        if (password.isEmpty()) {
            status = "请输入桌面端密码库的密钥"
            return
        }
        launchAction("正在下载并解密桌面端的密码库…") {
            val opened = repository.importFromHost(pairingText, password)
            locked = false
            "已从桌面端导入，共 " + opened.records.size + " 条"
        }
    }

    fun sync(pairingText: String) {
        if (pairingText.isBlank()) {
            status = "请先扫描或粘贴配对信息"
            return
        }
        launchAction("正在与桌面端同步…") {
            val conflicts = repository.sync(pairingText)
            if (conflicts.isEmpty()) {
                "同步完成"
            } else {
                "同步完成，" + conflicts.size + " 条冲突（两个版本都已保留）"
            }
        }
    }

    companion object {
        fun factory(repository: VaultRepository): ViewModelProvider.Factory = viewModelFactory {
            initializer { VaultViewModel(repository) }
        }
    }
}
