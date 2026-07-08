package com.example

import android.content.Context
import android.database.Cursor
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import java.io.BufferedOutputStream
import java.io.BufferedWriter
import java.io.IOException
import java.io.OutputStreamWriter
import java.nio.ByteBuffer
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

enum class ExportFormat { JSON, TEXT }

enum class ExportSection {
    HEADER,
    SYMBOLS,
    STRINGS,
    XREFS,
    ANNOTATIONS,
    DISASSEMBLY
}

data class ExportProgress(
    val section: ExportSection,
    val itemsWritten: Int,
    val estimatedTotal: Int?
)

object ExportManager {

    /**
     * Highly optimized, memory-mapped streaming analysis report exporter.
     */
    suspend fun exportReport(
        fileId: String,
        context: Context,
        format: ExportFormat,
        sections: Set<ExportSection>,
        outputUri: Uri,
        binaryBuffer: ByteBuffer?,
        elfHeader: ElfParser.ElfHeader?,
        onProgress: (ExportProgress) -> Unit
    ): Result<Unit> = withContext(Dispatchers.IO) {
        var outputStream: java.io.OutputStream = object : java.io.OutputStream() {
            override fun write(b: Int) {}
            override fun write(b: ByteArray) {}
            override fun write(b: ByteArray, off: Int, len: Int) {}
        }
        var writer: BufferedWriter? = null
        try {
            outputStream = context.contentResolver.openOutputStream(outputUri)
                ?: return@withContext Result.failure(IOException("Could not open output stream for selected location."))
            
            writer = BufferedWriter(OutputStreamWriter(BufferedOutputStream(outputStream), "UTF-8"))
            val dbHelper = OffsetsDatabaseHelper(context)

            if (format == ExportFormat.JSON) {
                exportJson(
                    fileId = fileId,
                    writer = writer,
                    sections = sections,
                    dbHelper = dbHelper,
                    binaryBuffer = binaryBuffer,
                    elfHeader = elfHeader,
                    onProgress = onProgress
                )
            } else {
                exportText(
                    fileId = fileId,
                    writer = writer,
                    sections = sections,
                    dbHelper = dbHelper,
                    binaryBuffer = binaryBuffer,
                    elfHeader = elfHeader,
                    onProgress = onProgress
                )
            }

            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        } finally {
            try {
                writer?.flush()
                writer?.close()
            } catch (ignored: Exception) {}
        }
    }

    private suspend fun exportJson(
        fileId: String,
        writer: BufferedWriter,
        sections: Set<ExportSection>,
        dbHelper: OffsetsDatabaseHelper,
        binaryBuffer: ByteBuffer?,
        elfHeader: ElfParser.ElfHeader?,
        onProgress: (ExportProgress) -> Unit
    ) {
        writer.write("{\n")
        writer.write("  \"fileId\": " + escapeJsonString(fileId) + ",\n")
        writer.write("  \"exportTimestamp\": " + System.currentTimeMillis())

        var needsComma = true

        // 1. HEADER
        if (sections.contains(ExportSection.HEADER)) {
            currentCoroutineContext().ensureActive()
            onProgress(ExportProgress(ExportSection.HEADER, 0, 1))
            if (needsComma) writer.write(",\n")
            writer.write("  \"header\": {\n")
            if (elfHeader != null) {
                writer.write("    \"isElf\": ${elfHeader.isElf},\n")
                writer.write("    \"is64Bit\": ${elfHeader.is64Bit},\n")
                writer.write("    \"isLittleEndian\": ${elfHeader.isLittleEndian},\n")
                writer.write("    \"machine\": " + escapeJsonString(elfHeader.machine) + ",\n")
                writer.write("    \"entryPoint\": " + escapeJsonString(elfHeader.entryPoint) + ",\n")
                writer.write("    \"classType\": " + escapeJsonString(elfHeader.classType) + ",\n")
                writer.write("    \"endianType\": " + escapeJsonString(elfHeader.endianType) + "\n")
            } else {
                writer.write("    \"isElf\": false,\n")
                writer.write("    \"classType\": \"RAW DATA (Non-ELF)\"\n")
            }
            writer.write("  }")
            onProgress(ExportProgress(ExportSection.HEADER, 1, 1))
            needsComma = true
        }

        // 2. SYMBOLS
        if (sections.contains(ExportSection.SYMBOLS)) {
            currentCoroutineContext().ensureActive()
            if (needsComma) writer.write(",\n")
            writer.write("  \"symbols\": [\n")
            
            val cursor = dbHelper.getSymbolsCursor(fileId)
            val count = cursor.count
            var index = 0
            
            cursor.use {
                val hexIdx = it.getColumnIndex("offset_hex")
                val nameIdx = it.getColumnIndex("symbol_name")
                
                while (it.moveToNext()) {
                    currentCoroutineContext().ensureActive()
                    val hex = if (hexIdx != -1) it.getString(hexIdx) else ""
                    val name = if (nameIdx != -1) it.getString(nameIdx) else ""
                    
                    writer.write("    {\"address\": \"$hex\", \"name\": ${escapeJsonString(name)}}")
                    
                    index++
                    if (index < count) {
                        writer.write(",\n")
                    } else {
                        writer.write("\n")
                    }
                    
                    if (index % 100 == 0 || index == count) {
                        onProgress(ExportProgress(ExportSection.SYMBOLS, index, count))
                    }
                }
            }
            writer.write("  ]")
            needsComma = true
        }

        // 3. STRINGS
        if (sections.contains(ExportSection.STRINGS)) {
            currentCoroutineContext().ensureActive()
            if (needsComma) writer.write(",\n")
            writer.write("  \"strings\": [\n")

            if (binaryBuffer != null) {
                val parser = ElfParser(binaryBuffer)
                val strings = parser.extractStrings()
                val total = strings.size
                
                strings.forEachIndexed { i, str ->
                    currentCoroutineContext().ensureActive()
                    writer.write("    {\"offset\": \"${str.offset}\", \"value\": ${escapeJsonString(str.value)}, \"length\": ${str.length}}")
                    if (i < total - 1) {
                        writer.write(",\n")
                    } else {
                        writer.write("\n")
                    }
                    
                    if (i % 100 == 0 || i == total - 1) {
                        onProgress(ExportProgress(ExportSection.STRINGS, i + 1, total))
                    }
                }
            }
            writer.write("  ]")
            needsComma = true
        }

        // 4. XREFS
        if (sections.contains(ExportSection.XREFS)) {
            currentCoroutineContext().ensureActive()
            if (needsComma) writer.write(",\n")
            writer.write("  \"xrefs\": [\n")

            val cursor = dbHelper.getXrefsCursor(fileId)
            val count = cursor.count
            var index = 0

            cursor.use {
                val fromIdx = it.getColumnIndex("from_addr")
                val toIdx = it.getColumnIndex("to_addr")
                val typeIdx = it.getColumnIndex("xref_type")

                while (it.moveToNext()) {
                    currentCoroutineContext().ensureActive()
                    val fromAddr = if (fromIdx != -1) it.getLong(fromIdx) else 0L
                    val toAddr = if (toIdx != -1) it.getLong(toIdx) else 0L
                    val type = if (typeIdx != -1) it.getString(typeIdx) else ""

                    val fromHex = "0x" + java.lang.Long.toHexString(fromAddr).uppercase()
                    val toHex = "0x" + java.lang.Long.toHexString(toAddr).uppercase()

                    writer.write("    {\"from\": \"$fromHex\", \"to\": \"$toHex\", \"type\": ${escapeJsonString(type)}}")

                    index++
                    if (index < count) {
                        writer.write(",\n")
                    } else {
                        writer.write("\n")
                    }

                    if (index % 100 == 0 || index == count) {
                        onProgress(ExportProgress(ExportSection.XREFS, index, count))
                    }
                }
            }
            writer.write("  ]")
            needsComma = true
        }

        // 5. ANNOTATIONS
        if (sections.contains(ExportSection.ANNOTATIONS)) {
            currentCoroutineContext().ensureActive()
            if (needsComma) writer.write(",\n")
            writer.write("  \"annotations\": [\n")

            val cursor = dbHelper.getAnnotationsCursor(fileId)
            val count = cursor.count
            var index = 0

            cursor.use {
                val addrIdx = it.getColumnIndex("address")
                val nameIdx = it.getColumnIndex("custom_name")
                val commentIdx = it.getColumnIndex("comment")
                val updatedIdx = it.getColumnIndex("updated_at")

                while (it.moveToNext()) {
                    currentCoroutineContext().ensureActive()
                    val addr = if (addrIdx != -1) it.getLong(addrIdx) else 0L
                    val name = if (nameIdx != -1 && !it.isNull(nameIdx)) it.getString(nameIdx) else null
                    val comment = if (commentIdx != -1 && !it.isNull(commentIdx)) it.getString(commentIdx) else null
                    val updated = if (updatedIdx != -1) it.getLong(updatedIdx) else 0L

                    val addrHex = "0x" + java.lang.Long.toHexString(addr).uppercase()

                    writer.write("    {\"address\": \"$addrHex\", \"customName\": ${escapeJsonString(name)}, \"comment\": ${escapeJsonString(comment)}, \"updatedAt\": $updated}")

                    index++
                    if (index < count) {
                        writer.write(",\n")
                    } else {
                        writer.write("\n")
                    }

                    if (index % 50 == 0 || index == count) {
                        onProgress(ExportProgress(ExportSection.ANNOTATIONS, index, count))
                    }
                }
            }
            writer.write("  ]")
            needsComma = true
        }

        // 6. DISASSEMBLY
        if (sections.contains(ExportSection.DISASSEMBLY)) {
            currentCoroutineContext().ensureActive()
            if (needsComma) writer.write(",\n")
            writer.write("  \"disassembly\": [\n")

            if (binaryBuffer != null && elfHeader != null) {
                val parser = ElfParser(binaryBuffer)
                val textSection = parser.findTextSection()
                if (textSection != null) {
                    val totalBytes = textSection.bytes.size
                    var bytesProcessed = 0
                    var itemsWritten = 0

                    // Stream 64KB chunks
                    while (bytesProcessed < totalBytes) {
                        currentCoroutineContext().ensureActive()
                        val chunkSize = minOf(65536, totalBytes - bytesProcessed)
                        val chunkBytes = ByteArray(chunkSize)
                        System.arraycopy(textSection.bytes, bytesProcessed, chunkBytes, 0, chunkSize)

                        val chunkVirtAddr = textSection.virtualAddress + bytesProcessed
                        val lines = parser.disassembleSection(
                            chunkBytes,
                            chunkVirtAddr,
                            elfHeader.machineVal,
                            elfHeader.is64Bit
                        )

                        if (lines != null) {
                            lines.forEachIndexed { lineIdx, line ->
                                currentCoroutineContext().ensureActive()
                                val addrHex = "0x" + java.lang.Long.toHexString(line.address).uppercase()
                                writer.write("    {\"address\": \"$addrHex\", \"bytes\": \"${line.bytesHex}\", \"mnemonic\": \"${line.mnemonic}\", \"operands\": ${escapeJsonString(line.opStr)}}")
                                
                                val isLastInChunk = lineIdx == lines.size - 1
                                val isLastChunk = (bytesProcessed + chunkSize) >= totalBytes
                                
                                if (isLastInChunk && isLastChunk) {
                                    writer.write("\n")
                                } else {
                                    writer.write(",\n")
                                }
                                itemsWritten++
                            }
                        }

                        bytesProcessed += chunkSize
                        onProgress(ExportProgress(ExportSection.DISASSEMBLY, itemsWritten, null))
                    }
                }
            }
            writer.write("  ]")
        }

        writer.write("\n}\n")
    }

    private suspend fun exportText(
        fileId: String,
        writer: BufferedWriter,
        sections: Set<ExportSection>,
        dbHelper: OffsetsDatabaseHelper,
        binaryBuffer: ByteBuffer?,
        elfHeader: ElfParser.ElfHeader?,
        onProgress: (ExportProgress) -> Unit
    ) {
        val dateFormat = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)
        val dateStr = dateFormat.format(Date())

        writer.write("================================================================================\n")
        writer.write("MINI-IDA BINARY ANALYSIS REPORT: $fileId\n")
        writer.write("Generated on: $dateStr\n")
        writer.write("================================================================================\n\n")

        // 1. HEADER
        if (sections.contains(ExportSection.HEADER)) {
            currentCoroutineContext().ensureActive()
            onProgress(ExportProgress(ExportSection.HEADER, 0, 1))
            writer.write("ELF HEADER INFORMATION\n")
            writer.write("----------------------\n")
            if (elfHeader != null) {
                writer.write(String.format(Locale.US, "%-15s %s\n", "Class:", elfHeader.classType))
                writer.write(String.format(Locale.US, "%-15s %s\n", "Machine:", elfHeader.machine))
                writer.write(String.format(Locale.US, "%-15s %s\n", "Entry Point:", elfHeader.entryPoint))
                writer.write(String.format(Locale.US, "%-15s %s\n", "Endianness:", elfHeader.endianType))
            } else {
                writer.write(String.format(Locale.US, "%-15s %s\n", "Class:", "RAW DATA (Non-ELF)"))
            }
            writer.write("\n")
            onProgress(ExportProgress(ExportSection.HEADER, 1, 1))
        }

        // 2. SYMBOLS
        if (sections.contains(ExportSection.SYMBOLS)) {
            currentCoroutineContext().ensureActive()
            writer.write("================================================================================\n")
            writer.write("FUNCTIONS / SYMBOLS TABLE\n")
            writer.write("================================================================================\n")
            writer.write(String.format(Locale.US, "%-18s %-60s\n", "Address", "Symbol Name"))
            writer.write("--------------------------------------------------------------------------------\n")

            val cursor = dbHelper.getSymbolsCursor(fileId)
            val count = cursor.count
            var index = 0

            cursor.use {
                val hexIdx = it.getColumnIndex("offset_hex")
                val nameIdx = it.getColumnIndex("symbol_name")

                while (it.moveToNext()) {
                    currentCoroutineContext().ensureActive()
                    val hex = if (hexIdx != -1) it.getString(hexIdx) else ""
                    val name = if (nameIdx != -1) it.getString(nameIdx) else ""

                    writer.write(String.format(Locale.US, "%-18s %-60s\n", hex, name))

                    index++
                    if (index % 100 == 0 || index == count) {
                        onProgress(ExportProgress(ExportSection.SYMBOLS, index, count))
                    }
                }
            }
            writer.write("\n")
        }

        // 3. STRINGS
        if (sections.contains(ExportSection.STRINGS)) {
            currentCoroutineContext().ensureActive()
            writer.write("================================================================================\n")
            writer.write("PRINTABLE STRINGS\n")
            writer.write("================================================================================\n")
            writer.write(String.format(Locale.US, "%-18s %-6s %-100s\n", "Offset", "Len", "Value"))
            writer.write("--------------------------------------------------------------------------------\n")

            if (binaryBuffer != null) {
                val parser = ElfParser(binaryBuffer)
                val strings = parser.extractStrings()
                val total = strings.size

                strings.forEachIndexed { i, str ->
                    currentCoroutineContext().ensureActive()
                    writer.write(String.format(Locale.US, "%-18s %-6d %-100s\n", str.offset, str.length, str.value))
                    if (i % 100 == 0 || i == total - 1) {
                        onProgress(ExportProgress(ExportSection.STRINGS, i + 1, total))
                    }
                }
            }
            writer.write("\n")
        }

        // 4. XREFS
        if (sections.contains(ExportSection.XREFS)) {
            currentCoroutineContext().ensureActive()
            writer.write("================================================================================\n")
            writer.write("CROSS-REFERENCES (XREFS)\n")
            writer.write("================================================================================\n")
            writer.write(String.format(Locale.US, "%-18s %-18s %-10s\n", "From Address", "To Address", "Type"))
            writer.write("--------------------------------------------------------------------------------\n")

            val cursor = dbHelper.getXrefsCursor(fileId)
            val count = cursor.count
            var index = 0

            cursor.use {
                val fromIdx = it.getColumnIndex("from_addr")
                val toIdx = it.getColumnIndex("to_addr")
                val typeIdx = it.getColumnIndex("xref_type")

                while (it.moveToNext()) {
                    currentCoroutineContext().ensureActive()
                    val fromAddr = if (fromIdx != -1) it.getLong(fromIdx) else 0L
                    val toAddr = if (toIdx != -1) it.getLong(toIdx) else 0L
                    val type = if (typeIdx != -1) it.getString(typeIdx) else ""

                    val fromHex = "0x" + java.lang.Long.toHexString(fromAddr).uppercase()
                    val toHex = "0x" + java.lang.Long.toHexString(toAddr).uppercase()

                    writer.write(String.format(Locale.US, "%-18s %-18s %-10s\n", fromHex, toHex, type))

                    index++
                    if (index % 100 == 0 || index == count) {
                        onProgress(ExportProgress(ExportSection.XREFS, index, count))
                    }
                }
            }
            writer.write("\n")
        }

        // 5. ANNOTATIONS
        if (sections.contains(ExportSection.ANNOTATIONS)) {
            currentCoroutineContext().ensureActive()
            writer.write("================================================================================\n")
            writer.write("USER ANNOTATIONS (NAMES & COMMENTS)\n")
            writer.write("================================================================================\n")
            writer.write(String.format(Locale.US, "%-18s %-30s %-50s\n", "Address", "Custom Name", "Comment"))
            writer.write("--------------------------------------------------------------------------------\n")

            val cursor = dbHelper.getAnnotationsCursor(fileId)
            val count = cursor.count
            var index = 0

            cursor.use {
                val addrIdx = it.getColumnIndex("address")
                val nameIdx = it.getColumnIndex("custom_name")
                val commentIdx = it.getColumnIndex("comment")

                while (it.moveToNext()) {
                    currentCoroutineContext().ensureActive()
                    val addr = if (addrIdx != -1) it.getLong(addrIdx) else 0L
                    val name = if (nameIdx != -1 && !it.isNull(nameIdx)) it.getString(nameIdx) else ""
                    val comment = if (commentIdx != -1 && !it.isNull(commentIdx)) it.getString(commentIdx) else ""

                    val addrHex = "0x" + java.lang.Long.toHexString(addr).uppercase()

                    writer.write(String.format(Locale.US, "%-18s %-30s %-50s\n", addrHex, name, comment))

                    index++
                    if (index % 50 == 0 || index == count) {
                        onProgress(ExportProgress(ExportSection.ANNOTATIONS, index, count))
                    }
                }
            }
            writer.write("\n")
        }

        // 6. DISASSEMBLY
        if (sections.contains(ExportSection.DISASSEMBLY)) {
            currentCoroutineContext().ensureActive()
            writer.write("================================================================================\n")
            writer.write("DISASSEMBLY (.text section)\n")
            writer.write("================================================================================\n")
            writer.write(String.format(Locale.US, "%-18s %-24s %-12s %-50s\n", "Address", "Bytes", "Mnemonic", "Operands"))
            writer.write("--------------------------------------------------------------------------------\n")

            if (binaryBuffer != null && elfHeader != null) {
                val parser = ElfParser(binaryBuffer)
                val textSection = parser.findTextSection()
                if (textSection != null) {
                    val totalBytes = textSection.bytes.size
                    var bytesProcessed = 0
                    var itemsWritten = 0

                    while (bytesProcessed < totalBytes) {
                        currentCoroutineContext().ensureActive()
                        val chunkSize = minOf(65536, totalBytes - bytesProcessed)
                        val chunkBytes = ByteArray(chunkSize)
                        System.arraycopy(textSection.bytes, bytesProcessed, chunkBytes, 0, chunkSize)

                        val chunkVirtAddr = textSection.virtualAddress + bytesProcessed
                        val lines = parser.disassembleSection(
                            chunkBytes,
                            chunkVirtAddr,
                            elfHeader.machineVal,
                            elfHeader.is64Bit
                        )

                        if (lines != null) {
                            lines.forEach { line ->
                                currentCoroutineContext().ensureActive()
                                val addrHex = "0x" + java.lang.Long.toHexString(line.address).uppercase()
                                writer.write(String.format(Locale.US, "%-18s %-24s %-12s %-50s\n", addrHex, line.bytesHex, line.mnemonic, line.opStr))
                                itemsWritten++
                            }
                        }

                        bytesProcessed += chunkSize
                        onProgress(ExportProgress(ExportSection.DISASSEMBLY, itemsWritten, null))
                    }
                }
            }
            writer.write("\n")
        }
    }

    private fun escapeJsonString(s: String?): String {
        if (s == null) return "null"
        val sb = StringBuilder()
        sb.append("\"")
        for (element in s) {
            when (element) {
                '\\' -> sb.append("\\\\")
                '"' -> sb.append("\\\"")
                '\b' -> sb.append("\\b")
                '\u000C' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else -> {
                    if (element.code < 32 || element.code > 126) {
                        sb.append(String.format(Locale.US, "\\u%04x", element.code))
                    } else {
                        sb.append(element)
                    }
                }
            }
        }
        sb.append("\"")
        return sb.toString()
    }
}
