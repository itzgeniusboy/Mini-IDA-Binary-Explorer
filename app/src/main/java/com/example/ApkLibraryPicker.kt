package com.example

import android.app.Dialog
import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ExpandLess
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.util.Locale

// Theme colors matching the existing palette in colors.xml
private val CyberBg = Color(0xFF090A0F)
private val CyberSurface = Color(0xFF121420)
private val CyberCard = Color(0xFF1A1D2E)
private val CyberGreen = Color(0xFF00FF66)
private val CyberCyan = Color(0xFF00E5FF)
private val CyberPink = Color(0xFFFF007F)
private val CyberTextPrimary = Color(0xFFF1F5F9)
private val CyberTextSecondary = Color(0xFF94A3B8)
private val CyberTextMuted = Color(0xFF64748B)
private val CyberBorder = Color(0xFF2A2E45)

object ApkLibraryPicker {

    fun show(
        context: Context,
        apkUri: Uri,
        fileId: String,
        nativeLibs: List<ApkInspector.ApkNativeLib>,
        onLibraryExtracted: (File, String) -> Unit,
        onDismiss: () -> Unit
    ) {
        val dialog = Dialog(context)
        dialog.setCancelable(true)
        dialog.setCanceledOnTouchOutside(false) // Do not dismiss accidentally during extraction
        dialog.setOnDismissListener { onDismiss() }

        val composeView = ComposeView(context).apply {
            setContent {
                MaterialTheme(
                    colorScheme = darkColorScheme(
                        background = CyberBg,
                        surface = CyberSurface,
                        primary = CyberGreen,
                        secondary = CyberCyan,
                        onBackground = CyberTextPrimary,
                        onSurface = CyberTextPrimary
                    )
                ) {
                    ApkLibraryPickerContent(
                        context = context,
                        apkUri = apkUri,
                        fileId = fileId,
                        nativeLibs = nativeLibs,
                        onLibraryExtracted = { file, displayName ->
                            dialog.dismiss()
                            onLibraryExtracted(file, displayName)
                        },
                        onCancel = {
                            dialog.dismiss()
                            onDismiss()
                        }
                    )
                }
            }
        }

        dialog.setContentView(composeView)
        dialog.show()
        
        dialog.window?.apply {
            setBackgroundDrawableResource(android.R.color.transparent)
            setLayout(
                android.view.ViewGroup.LayoutParams.MATCH_PARENT,
                android.view.ViewGroup.LayoutParams.WRAP_CONTENT
            )
        }
    }
}

@Composable
fun ApkLibraryPickerContent(
    context: Context,
    apkUri: Uri,
    fileId: String,
    nativeLibs: List<ApkInspector.ApkNativeLib>,
    onLibraryExtracted: (File, String) -> Unit,
    onCancel: () -> Unit
) {
    val preferredAbi = remember { Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a" }
    val coroutineScope = rememberCoroutineScope()
    
    // Extraction states
    var extractionProgress by remember { mutableStateOf<Float?>(null) }
    var extractingLibName by remember { mutableStateOf<String?>(null) }

    val libsByAbi = remember(nativeLibs) {
        nativeLibs.groupBy { it.abi }
    }
    
    val sortedAbis = remember(libsByAbi) {
        libsByAbi.keys.sortedWith { abi1, abi2 ->
            when {
                abi1 == preferredAbi && abi2 != preferredAbi -> -1
                abi1 != preferredAbi && abi2 == preferredAbi -> 1
                else -> abi1.compareTo(abi2)
            }
        }
    }
    
    val expandedStates = remember(sortedAbis) {
        mutableStateMapOf<String, Boolean>().apply {
            sortedAbis.forEach { abi ->
                // Expand the preferred ABI by default
                this[abi] = (abi == preferredAbi)
            }
        }
    }

    Box(modifier = Modifier.fillMaxWidth()) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
                .border(1.dp, CyberBorder, RoundedCornerShape(12.dp))
                .testTag("apk_picker_dialog_card"),
            shape = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(containerColor = CyberSurface)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
            ) {
                // Header
                Text(
                    text = "SELECT NATIVE LIBRARY",
                    color = CyberGreen,
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier
                        .align(Alignment.CenterHorizontally)
                        .testTag("apk_picker_title")
                )
                
                Spacer(modifier = Modifier.height(4.dp))
                
                Text(
                    text = "Multiple embedded libraries (.so) were detected inside the APK. Please pick one to inspect.",
                    color = CyberTextSecondary,
                    fontSize = 12.sp,
                    fontFamily = FontFamily.Monospace,
                    modifier = Modifier.align(Alignment.CenterHorizontally),
                    textAlign = TextAlign.Center
                )
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Native Library List (Expanded heights capped at 320dp for usability)
                Box(modifier = Modifier.heightIn(max = 320.dp)) {
                    if (nativeLibs.isEmpty()) {
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(24.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = "NO NATIVE LIBRARIES FOUND (.so)",
                                color = CyberPink,
                                fontWeight = FontWeight.Bold,
                                fontFamily = FontFamily.Monospace,
                                fontSize = 13.sp
                            )
                        }
                    } else {
                        LazyColumn(
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            sortedAbis.forEach { abi ->
                                val isPreferred = abi == preferredAbi
                                val isExpanded = expandedStates[abi] ?: false
                                val libs = libsByAbi[abi] ?: emptyList()
                                
                                item {
                                    // ABI Section Header Row
                                    Row(
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .background(CyberCard, RoundedCornerShape(6.dp))
                                            .border(1.dp, if (isPreferred) CyberGreen else CyberBorder, RoundedCornerShape(6.dp))
                                            .clickable { expandedStates[abi] = !isExpanded }
                                            .padding(12.dp)
                                            .testTag("abi_header_$abi"),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Column(modifier = Modifier.weight(1f)) {
                                            Row(verticalAlignment = Alignment.CenterVertically) {
                                                Text(
                                                    text = abi.uppercase(),
                                                    color = if (isPreferred) CyberGreen else CyberTextPrimary,
                                                    fontWeight = FontWeight.Bold,
                                                    fontFamily = FontFamily.Monospace,
                                                    fontSize = 14.sp
                                                )
                                                if (isPreferred) {
                                                    Spacer(modifier = Modifier.width(8.dp))
                                                    Box(
                                                        modifier = Modifier
                                                            .background(CyberGreen.copy(alpha = 0.15f), RoundedCornerShape(4.dp))
                                                            .border(0.5.dp, CyberGreen, RoundedCornerShape(4.dp))
                                                            .padding(horizontal = 6.dp, vertical = 2.dp)
                                                    ) {
                                                        Text(
                                                            text = "RECOMMENDED",
                                                            color = CyberGreen,
                                                            fontSize = 9.sp,
                                                            fontWeight = FontWeight.Bold,
                                                            fontFamily = FontFamily.Monospace
                                                        )
                                                    }
                                                }
                                            }
                                            Text(
                                                text = "${libs.size} libraries found",
                                                color = CyberTextMuted,
                                                fontSize = 11.sp,
                                                fontFamily = FontFamily.Monospace
                                            )
                                        }
                                        
                                        Icon(
                                            imageVector = if (isExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                                            contentDescription = if (isExpanded) "Collapse" else "Expand",
                                            tint = if (isPreferred) CyberGreen else CyberTextSecondary
                                        )
                                    }
                                }
                                
                                if (isExpanded) {
                                    items(libs) { lib ->
                                        Row(
                                            modifier = Modifier
                                                .fillMaxWidth()
                                                .padding(horizontal = 8.dp)
                                                .background(CyberBg, RoundedCornerShape(4.dp))
                                                .border(0.5.dp, CyberBorder, RoundedCornerShape(4.dp))
                                                .clickable {
                                                    if (extractionProgress == null) {
                                                        extractingLibName = lib.libraryName
                                                        extractionProgress = 0f
                                                        coroutineScope.launch {
                                                            val file = withContext(Dispatchers.IO) {
                                                                ApkInspector.extractLibrary(
                                                                    context = context,
                                                                    apkUri = apkUri,
                                                                    fileId = fileId,
                                                                    lib = lib,
                                                                    onProgress = { progress ->
                                                                        extractionProgress = progress
                                                                    }
                                                                )
                                                            }
                                                            if (file != null) {
                                                                onLibraryExtracted(file, "${lib.libraryName} (${lib.abi})")
                                                            } else {
                                                                extractionProgress = null
                                                                extractingLibName = null
                                                                android.widget.Toast.makeText(
                                                                    context,
                                                                    "Failed to extract native library.",
                                                                    android.widget.Toast.LENGTH_SHORT
                                                                ).show()
                                                            }
                                                        }
                                                    }
                                                }
                                                .padding(12.dp)
                                                .testTag("lib_item_${lib.libraryName}"),
                                            verticalAlignment = Alignment.CenterVertically
                                        ) {
                                            Column(modifier = Modifier.weight(1f)) {
                                                Text(
                                                    text = lib.libraryName,
                                                    color = CyberCyan,
                                                    fontWeight = FontWeight.SemiBold,
                                                    fontFamily = FontFamily.Monospace,
                                                    fontSize = 13.sp
                                                )
                                                Text(
                                                    text = "Path: ${lib.entryName}",
                                                    color = CyberTextMuted,
                                                    fontSize = 10.sp,
                                                    fontFamily = FontFamily.Monospace
                                                )
                                            }
                                            Spacer(modifier = Modifier.width(8.dp))
                                            Text(
                                                text = formatBytes(lib.sizeBytes),
                                                color = CyberTextSecondary,
                                                fontSize = 11.sp,
                                                fontFamily = FontFamily.Monospace
                                            )
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                // Buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    TextButton(
                        onClick = onCancel,
                        enabled = extractionProgress == null,
                        modifier = Modifier.testTag("apk_picker_cancel_button")
                    ) {
                        Text(
                            text = "CANCEL",
                            color = if (extractionProgress == null) CyberTextSecondary else CyberTextMuted,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }

        // Overlay during extraction
        extractionProgress?.let { progress ->
            Box(
                modifier = Modifier
                    .matchParentSize()
                    .padding(16.dp)
                    .background(CyberBg.copy(alpha = 0.85f), RoundedCornerShape(12.dp))
                    .clickable(enabled = false) {}, // Scrim
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    modifier = Modifier.padding(24.dp)
                ) {
                    CircularProgressIndicator(
                        progress = { progress },
                        color = CyberGreen,
                        strokeWidth = 4.dp,
                    )
                    
                    Spacer(modifier = Modifier.height(16.dp))
                    
                    Text(
                        text = "EXTRACTING ${extractingLibName?.uppercase() ?: "LIBRARY"}...",
                        color = CyberGreen,
                        fontWeight = FontWeight.Bold,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 14.sp,
                        textAlign = TextAlign.Center
                    )
                    
                    Spacer(modifier = Modifier.height(8.dp))
                    
                    Text(
                        text = "Progress: ${(progress * 100).toInt()}%",
                        color = CyberTextSecondary,
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp
                    )
                }
            }
        }
    }
}

private fun formatBytes(bytes: Long): String {
    if (bytes <= 0) return "Unknown size"
    if (bytes < 1024) return "$bytes B"
    val exp = (Math.log(bytes.toDouble()) / Math.log(1024.0)).toInt()
    val pre = "KMGTPE"[exp - 1]
    return String.format(Locale.US, "%.1f %sB", bytes / Math.pow(1024.0, exp.toDouble()), pre)
}
