package com.example

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.ui.theme.*

fun formatSize(bytes: Long): String {
    val kb = bytes / 1024.0
    val mb = kb / 1024.0
    val gb = mb / 1024.0
    return when {
        gb >= 1.0 -> String.format("%.2f GB", gb)
        mb >= 1.0 -> String.format("%.2f MB", mb)
        kb >= 1.0 -> String.format("%.2f KB", kb)
        else -> "$bytes Bytes"
    }
}

@Composable
fun LoadingProgressScreen(
    progress: LoadProgress?,
    onCancel: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(24.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, DarkBorder)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "ANALYZING BINARY",
                color = CyberPrimary,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            val stage = progress?.stage ?: LoadStage.READING_HEADER
            val details = progress?.detail ?: "Initializing parser..."
            val itemsProcessed = progress?.itemsProcessed ?: 0

            val progressFraction = when (stage) {
                LoadStage.READING_HEADER -> 0.15f
                LoadStage.PARSING_SECTIONS -> 0.35f
                LoadStage.EXTRACTING_SYMBOLS -> 0.50f
                LoadStage.EXTRACTING_STRINGS -> 0.65f
                LoadStage.INDEXING_DB -> 0.80f
                LoadStage.MATCHING_SIGNATURES -> 0.90f
                LoadStage.RESOLVING_DATA_XREFS -> 0.94f
                LoadStage.DETECTING_JUMP_TABLES -> 0.97f
                LoadStage.DONE -> 1.0f
                LoadStage.ERROR -> 1.0f
            }

            LinearProgressIndicator(
                progress = { progressFraction },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp)
                    .background(DarkBg, RoundedCornerShape(3.dp)),
                color = CyberPrimary,
                trackColor = DarkBg
            )

            Spacer(modifier = Modifier.height(24.dp))

            val stageTitle = when (stage) {
                LoadStage.READING_HEADER -> "READING ELF HEADER"
                LoadStage.PARSING_SECTIONS -> "PARSING ELF SECTIONS"
                LoadStage.EXTRACTING_SYMBOLS -> "EXTRACTING SYMBOLS"
                LoadStage.EXTRACTING_STRINGS -> "EXTRACTING STRINGS"
                LoadStage.INDEXING_DB -> "INDEXING DATABASE"
                LoadStage.MATCHING_SIGNATURES -> "MATCHING SIGNATURES"
                LoadStage.RESOLVING_DATA_XREFS -> "RESOLVING DATA XREFS"
                LoadStage.DETECTING_JUMP_TABLES -> "DETECTING JUMP TABLES"
                LoadStage.DONE -> "ANALYSIS COMPLETE"
                LoadStage.ERROR -> "ANALYSIS ERROR"
            }

            // Stage title
            Text(
                text = stageTitle,
                color = TextPrimary,
                style = CodeTypography.monospaceMedium,
                fontWeight = FontWeight.SemiBold,
                textAlign = TextAlign.Center
            )

            Spacer(modifier = Modifier.height(12.dp))

            // Progress details
            Text(
                text = details,
                color = TextSecondary,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                modifier = Modifier.heightIn(min = 40.dp)
            )

            if (itemsProcessed > 0) {
                Spacer(modifier = Modifier.height(12.dp))
                Surface(
                    color = DarkBg,
                    shape = RoundedCornerShape(6.dp),
                    border = BorderStroke(0.5.dp, DarkBorder),
                    modifier = Modifier.padding(horizontal = 16.dp)
                ) {
                    Text(
                        text = "Processed: $itemsProcessed",
                        color = CyberSuccess,
                        style = CodeTypography.monospaceMedium,
                        fontWeight = FontWeight.Medium,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(28.dp))

            Button(
                onClick = onCancel,
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.Transparent,
                    contentColor = CyberError
                ),
                shape = RoundedCornerShape(8.dp),
                border = BorderStroke(1.dp, CyberError),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp) // Minimum touch target height
                    .testTag("cancel_load_button")
            ) {
                Text(
                    text = "CANCEL ANALYSIS",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}

@Composable
fun LowRamWarningScreen(
    fileSize: Long,
    availableRam: Long,
    totalRam: Long,
    fromApkPicker: Boolean,
    onProceed: () -> Unit,
    onCancel: () -> Unit,
    onChooseDifferentAbi: (() -> Unit)? = null
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(20.dp),
        colors = CardDefaults.cardColors(containerColor = DarkSurface),
        shape = RoundedCornerShape(16.dp),
        border = BorderStroke(1.dp, CyberError)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(
                text = "⚠️ MEMORY LIMIT WARNING",
                color = CyberError,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
                modifier = Modifier.padding(bottom = 16.dp)
            )

            Text(
                text = "The target binary is very large relative to your device's current available memory. Loading it may cause UI unresponsiveness, freezing, or an Out-Of-Memory (OOM) crash.",
                color = TextPrimary,
                style = MaterialTheme.typography.bodyMedium,
                textAlign = TextAlign.Center,
                lineHeight = 20.sp
            )

            Spacer(modifier = Modifier.height(20.dp))

            // Memory stats
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(DarkCard, RoundedCornerShape(8.dp))
                    .border(1.dp, DarkBorder, RoundedCornerShape(8.dp))
                    .padding(16.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("File Size:", color = TextSecondary, style = CodeTypography.monospaceSmall)
                    Text(formatSize(fileSize), color = CyberPrimary, style = CodeTypography.monospaceSmall, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Available RAM:", color = TextSecondary, style = CodeTypography.monospaceSmall)
                    Text(formatSize(availableRam), color = CyberError, style = CodeTypography.monospaceSmall, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text("Total Device RAM:", color = TextSecondary, style = CodeTypography.monospaceSmall)
                    Text(formatSize(totalRam), color = TextPrimary, style = CodeTypography.monospaceSmall)
                }
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Actions
            Button(
                onClick = onProceed,
                colors = ButtonDefaults.buttonColors(containerColor = CyberSuccess, contentColor = DarkBg),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .testTag("proceed_load_button")
            ) {
                Text(
                    text = "PROCEED",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold
                )
            }

            if (fromApkPicker && onChooseDifferentAbi != null) {
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = onChooseDifferentAbi,
                    colors = ButtonDefaults.buttonColors(containerColor = CyberPrimary, contentColor = DarkBg),
                    shape = RoundedCornerShape(8.dp),
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                        .testTag("choose_different_abi_button")
                ) {
                    Text(
                        text = "TRY DIFFERENT ABI",
                        style = MaterialTheme.typography.labelLarge,
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))
            OutlinedButton(
                onClick = onCancel,
                border = BorderStroke(1.dp, DarkBorder),
                colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary),
                shape = RoundedCornerShape(8.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(48.dp)
                    .testTag("cancel_warning_button")
            ) {
                Text(
                    text = "ABORT",
                    style = MaterialTheme.typography.labelLarge,
                    fontWeight = FontWeight.Bold
                )
            }
        }
    }
}
