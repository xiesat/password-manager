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

    val vaultId: String? get() = repository.state?.vaultId
    val deviceId: String get() = repository.deviceId

    private fun refresh() {
        records = repository.state?.records?.toList() ?: emptyList()
        hasVault = repository.exists()
    }

    private fun launchAction(block: suspend () -> String) {
        viewModelScope.launch {
            busy = true
            try {
                status = withContext(Dispatchers.IO) { block() }
                refresh()
            } catch (error: Exception) {
                status = "失败：" + (error.message ?: error.javaClass.simpleName)
            } finally {
                busy = false
            }
        }
    }

    fun createVault(password: String) {
        if (password.length < 6) {
            status = "密钥至少 6 位"
            return
        }
        launchAction {
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
        launchAction {
            repository.unlock(password)
            locked = false
            "解锁成功"
        }
    }

    fun lock() {
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
        launchAction {
            repository.addEntry(name.trim(), length, lower, upper, digit, symbol)
            "已添加并生成密码"
        }
    }

    fun delete(index: Int) {
        launchAction {
            repository.deleteEntries(listOf(index))
            "已删除"
        }
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
        launchAction {
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
        launchAction {
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
