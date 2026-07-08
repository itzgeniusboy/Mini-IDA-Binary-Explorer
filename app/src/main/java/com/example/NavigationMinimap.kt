package com.example

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.layout.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.unit.dp
import com.example.ui.theme.*

// Pre-computed function model for ultra-fast drawing
data class MinimapFunctionSegment(
    val startAddress: Long,
    val endAddress: Long,
    val isCustomNamed: Boolean
)

@Composable
fun NavigationMinimap(
    textSectionStart: Long,
    textSectionSize: Long,
    functions: List<ElfParser.ElfFunction>,
    visibleStartAddr: Long,
    visibleEndAddr: Long,
    bookmarks: List<BookmarkEntry>,
    onNavigateToAddress: (Long) -> Unit,
    modifier: Modifier = Modifier
) {
    if (textSectionSize <= 0L) return

    // Pre-compute the function segments to avoid calculating them during draw phases.
    val functionSegments = remember(functions) {
        functions.mapNotNull { f ->
            val addr = f.address.removePrefix("0x").removePrefix("0X").toLongOrNull(16)
            val size = f.size.substringBefore(" ").toLongOrNull() ?: 0L
            if (addr != null && addr >= textSectionStart && addr < textSectionStart + textSectionSize) {
                val isCustom = AnnotationRepository.getAnnotation(addr)?.customName?.isNotBlank() == true
                MinimapFunctionSegment(
                    startAddress = addr,
                    endAddress = addr + size,
                    isCustomNamed = isCustom
                )
            } else {
                null
            }
        }
    }

    // Capture height for coordinate mapping
    var canvasHeight by remember { mutableStateOf(1f) }

    val handleGestureInput: (Offset) -> Unit = { offset ->
        val relativeY = offset.y.coerceIn(0f, canvasHeight)
        val fraction = relativeY / canvasHeight
        val targetAddress = textSectionStart + (fraction * textSectionSize).toLong()
        onNavigateToAddress(targetAddress)
    }

    Box(
        modifier = modifier
            .fillMaxHeight()
            .width(32.dp)
            .background(DarkSurface)
            .pointerInput(Unit) {
                detectTapGestures(
                    onPress = { offset ->
                        handleGestureInput(offset)
                    }
                )
            }
            .pointerInput(Unit) {
                detectDragGestures { change, _ ->
                    change.consume()
                    handleGestureInput(change.position)
                }
            }
    ) {
        Canvas(
            modifier = Modifier
                .fillMaxSize()
                .padding(vertical = 4.dp) // Leave a tiny padding at the top/bottom
        ) {
            canvasHeight = size.height
            val height = size.height
            val width = size.width

            // 1. Draw a thin dividing left-border line
            drawLine(
                color = DarkBorder,
                start = Offset(0f, 0f),
                end = Offset(0f, height),
                strokeWidth = 1.dp.toPx()
            )

            // 2. Draw function segments
            val baseFuncColor = TextMuted.copy(alpha = 0.5f)
            val identifiedFuncColor = CyberSuccess.copy(alpha = 0.85f)

            for (segment in functionSegments) {
                val startFrac = (segment.startAddress - textSectionStart).toFloat() / textSectionSize
                val endFrac = (segment.endAddress - textSectionStart).toFloat() / textSectionSize

                val yStart = startFrac * height
                val yEnd = endFrac * height
                val segmentHeight = (yEnd - yStart).coerceAtLeast(1.dp.toPx())

                drawRect(
                    color = if (segment.isCustomNamed) identifiedFuncColor else baseFuncColor,
                    topLeft = Offset(4.dp.toPx(), yStart),
                    size = Size(width - 8.dp.toPx(), segmentHeight)
                )
            }

            // 3. Draw Bookmark tick marks
            val bookmarkColor = CyberError
            for (bookmark in bookmarks) {
                if (bookmark.address in textSectionStart until (textSectionStart + textSectionSize)) {
                    val frac = (bookmark.address - textSectionStart).toFloat() / textSectionSize
                    val y = frac * height
                    drawLine(
                        color = bookmarkColor,
                        start = Offset(2.dp.toPx(), y),
                        end = Offset(width - 2.dp.toPx(), y),
                        strokeWidth = 2.dp.toPx()
                    )
                }
            }

            // 4. Draw current visible scroll range overlay
            if (visibleStartAddr >= textSectionStart && visibleEndAddr <= textSectionStart + textSectionSize && visibleEndAddr > visibleStartAddr) {
                val startFrac = (visibleStartAddr - textSectionStart).toFloat() / textSectionSize
                val endFrac = (visibleEndAddr - textSectionStart).toFloat() / textSectionSize

                val yStart = startFrac * height
                val yEnd = endFrac * height
                val highlightHeight = (yEnd - yStart).coerceAtLeast(8.dp.toPx()) // Ensure highlight is easily visible

                // Draw semi-transparent background overlay
                drawRect(
                    color = CyberPrimary.copy(alpha = 0.15f),
                    topLeft = Offset(2.dp.toPx(), yStart),
                    size = Size(width - 4.dp.toPx(), highlightHeight)
                )

                // Draw bounding bracket/border
                drawRect(
                    color = CyberPrimary,
                    topLeft = Offset(2.dp.toPx(), yStart),
                    size = Size(width - 4.dp.toPx(), highlightHeight),
                    style = Stroke(width = 1.dp.toPx())
                )
            }
        }
    }
}
