package com.pmvault.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.lifecycle.viewmodel.compose.viewModel
import com.pmvault.app.ui.VaultApp

class MainActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val repository = VaultRepository(applicationContext)

        setContent {
            MaterialTheme {
                Surface {
                    val viewModel: VaultViewModel =
                        viewModel(factory = VaultViewModel.factory(repository))
                    VaultApp(viewModel)
                }
            }
        }
    }
}
