package com.pmvault.app.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.pmvault.app.VaultViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultApp(viewModel: VaultViewModel) {
    var showAdd by remember { mutableStateOf(false) }
    var showSync by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("密码管理器") },
                actions = {
                    // 未解锁时也允许打开：新手机需要用它"从桌面端导入"
                    TextButton(onClick = { showSync = true }) { Text("同步") }
                    if (!viewModel.locked) {
                        TextButton(onClick = { viewModel.lock() }) { Text("锁定") }
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            if (viewModel.locked) {
                UnlockScreen(viewModel)
            } else {
                VaultListScreen(viewModel, onAdd = { showAdd = true })
            }
            if (viewModel.busy) {
                LinearProgressIndicator(modifier = Modifier.fillMaxWidth())
            }
            if (viewModel.status.isNotEmpty()) {
                Text(
                    text = viewModel.status,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 6.dp),
                )
            }
        }
    }

    if (showAdd) {
        AddEntryDialog(viewModel) { showAdd = false }
    }
    if (showSync) {
        SyncDialog(viewModel) { showSync = false }
    }
}

@Composable
private fun UnlockScreen(viewModel: VaultViewModel) {
    var password by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.Center,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = if (viewModel.hasVault) "输入密钥解锁" else "创建新的密码库",
            style = MaterialTheme.typography.titleLarge,
        )
        Spacer(Modifier.height(16.dp))
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("密钥") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(16.dp))
        if (viewModel.hasVault) {
            Button(
                onClick = { viewModel.unlock(password) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("解锁") }
        } else {
            Button(
                onClick = { viewModel.createVault(password) },
                modifier = Modifier.fillMaxWidth(),
            ) { Text("创建") }
            Spacer(Modifier.height(8.dp))
            Text(
                text = "密钥丢失将无法恢复数据，请务必牢记。",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VaultListScreen(viewModel: VaultViewModel, onAdd: () -> Unit) {
    val clipboard = LocalClipboardManager.current
    var reveal by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = onAdd) { Text("新增主体") }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(onClick = { reveal = !reveal }) {
                Text(if (reveal) "隐藏密码" else "显示密码")
            }
        }

        LazyColumn(modifier = Modifier.fillMaxSize()) {
            itemsIndexed(viewModel.records) { index, record ->
                val name = record["name"] as? String ?: ""
                val password = record["password"] as? String ?: ""
                ListItem(
                    headlineContent = { Text(name) },
                    supportingContent = { Text(if (reveal) password else "••••••••") },
                    trailingContent = {
                        Row {
                            TextButton(onClick = { clipboard.setText(AnnotatedString(password)) }) {
                                Text("复制")
                            }
                            TextButton(onClick = { viewModel.delete(index) }) { Text("删除") }
                        }
                    },
                )
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun AddEntryDialog(viewModel: VaultViewModel, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf("") }
    var length by remember { mutableStateOf(16f) }
    var lower by remember { mutableStateOf(true) }
    var upper by remember { mutableStateOf(true) }
    var digit by remember { mutableStateOf(true) }
    var symbol by remember { mutableStateOf(true) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("新增密码主体") },
        text = {
            Column {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("名称") },
                    singleLine = true,
                )
                Spacer(Modifier.height(8.dp))
                Text("密码长度：" + length.toInt())
                Slider(value = length, onValueChange = { length = it }, valueRange = 6f..64f)
                CheckRow("小写字母 (a-z)", lower) { lower = it }
                CheckRow("大写字母 (A-Z)", upper) { upper = it }
                CheckRow("数字 (0-9)", digit) { digit = it }
                CheckRow("特殊字符 (!@#$)", symbol) { symbol = it }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    viewModel.addEntry(name, length.toInt(), lower, upper, digit, symbol)
                    onDismiss()
                },
            ) { Text("确定") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

@Composable
private fun CheckRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Checkbox(checked = checked, onCheckedChange = onChange)
        Text(label)
    }
}

@Composable
private fun SyncDialog(viewModel: VaultViewModel, onDismiss: () -> Unit) {
    var pairingText by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmImport by remember { mutableStateOf(false) }

    val scanner = rememberLauncherForActivityResult(ScanContract()) { result ->
        result.contents?.let { pairingText = it }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("局域网同步") },
        text = {
            Column {
                Text("1. 桌面端打开「同步 → 局域网同步…」，显示配对二维码。")
                Text("2. 本机点「扫描二维码」，或把配对信息粘贴到下面。")
                Spacer(Modifier.height(12.dp))
                Button(
                    onClick = {
                        val options = ScanOptions()
                        options.setDesiredBarcodeFormats(ScanOptions.QR_CODE)
                        options.setPrompt("扫描桌面端同步窗口中的二维码")
                        options.setBeepEnabled(false)
                        options.setOrientationLocked(false)
                        scanner.launch(options)
                    },
                ) { Text("扫描二维码") }
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = pairingText,
                    onValueChange = { pairingText = it },
                    label = { Text("配对信息") },
                    minLines = 2,
                )
                Spacer(Modifier.height(8.dp))
                OutlinedTextField(
                    value = password,
                    onValueChange = { password = it },
                    label = { Text("密码库密钥（导入时用）") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    text = "· 本机已是同一个库 → 点「同步」\n· 新手机首次使用 → 点「从桌面端导入」",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        },
        confirmButton = {
            TextButton(
                enabled = !viewModel.locked,
                onClick = {
                    viewModel.sync(pairingText)
                    onDismiss()
                },
            ) { Text("同步") }
        },
        dismissButton = {
            Row {
                TextButton(onClick = onDismiss) { Text("取消") }
                TextButton(
                    onClick = {
                        if (viewModel.hasVault) {
                            confirmImport = true
                        } else {
                            viewModel.importFromHost(pairingText, password)
                            onDismiss()
                        }
                    },
                ) { Text("从桌面端导入") }
            }
        },
    )

    if (confirmImport) {
        AlertDialog(
            onDismissRequest = { confirmImport = false },
            title = { Text("确认导入") },
            text = { Text("导入会用桌面端的密码库替换本机现有的库，本机当前数据将丢失。确定继续？") },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmImport = false
                        viewModel.importFromHost(pairingText, password)
                        onDismiss()
                    },
                ) { Text("确定导入") }
            },
            dismissButton = {
                TextButton(onClick = { confirmImport = false }) { Text("取消") }
            },
        )
    }
}
