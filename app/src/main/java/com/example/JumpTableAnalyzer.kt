package com.example

import java.nio.ByteBuffer
import java.nio.ByteOrder

object JumpTableAnalyzer {

    fun analyze(
        disassembly: List<DisassemblyLine>,
        sections: List<ElfParser.SectionInfo>,
        buffer: ByteBuffer?,
        isLittleEndian: Boolean,
        arch: ElfArch,
        is64Bit: Boolean
    ): List<JumpTableInfo> {
        if (disassembly.isEmpty()) return emptyList()

        val textSection = sections.find { it.name == ".text" }
        val textStart = textSection?.startAddress ?: disassembly.first().address
        val textEnd = textSection?.let { it.startAddress + it.size } ?: (disassembly.last().address + 4)

        val results = mutableListOf<JumpTableInfo>()

        for (idx in disassembly.indices) {
            val line = disassembly[idx]
            val mnem = line.mnemonic.trim().lowercase()
            val op = line.opStr.trim()

            var tableBaseAddr: Long? = null

            when (arch) {
                ElfArch.ARM64 -> {
                    // ARM64 indirect branch: br <reg> or blr <reg>
                    if (mnem == "br" || mnem == "blr") {
                        val reg = op.trim()
                        tableBaseAddr = findArm64TableBase(disassembly, idx, reg)
                    }
                }
                ElfArch.ARM32 -> {
                    // ARM32: ldr pc, [pc, rN, lsl #2] or ldr pc, [pc, rN]
                    if (mnem.startsWith("ldr") && op.trim().lowercase().startsWith("pc")) {
                        if (op.contains("[pc", ignoreCase = true)) {
                            // Standard PC-indexed table: base is PC + 8
                            tableBaseAddr = line.address + 8
                        }
                    }
                }
                ElfArch.X86, ElfArch.X86_64 -> {
                    // x86/x86_64: jmp [table_base + reg*scale]
                    if (mnem == "jmp") {
                        tableBaseAddr = findX86TableBase(op)
                    }
                }
                else -> {}
            }

            if (tableBaseAddr != null && tableBaseAddr > 0L) {
                val targets = resolveTableTargets(
                    tableBaseAddr = tableBaseAddr,
                    buffer = buffer,
                    isLittleEndian = isLittleEndian,
                    sections = sections,
                    textStart = textStart,
                    textEnd = textEnd,
                    is64Bit = is64Bit
                )
                if (targets.isNotEmpty()) {
                    results.add(
                        JumpTableInfo(
                            branchInstructionAddr = line.address,
                            tableBaseAddr = tableBaseAddr,
                            entryCount = targets.size,
                            caseTargets = targets
                        )
                    )
                }
            }
        }

        return results
    }

    private fun findArm64TableBase(
        disassembly: List<DisassemblyLine>,
        branchIdx: Int,
        branchReg: String
    ): Long? {
        val maxLookback = 15
        val startIdx = (branchIdx - 1).coerceAtLeast(0)
        val endIdx = (branchIdx - maxLookback).coerceAtLeast(0)

        var baseReg: String? = null
        var loadIdx = -1

        // Step 1: Find the ldr/ldrsw that loads branchReg
        for (i in startIdx downTo endIdx) {
            val line = disassembly[i]
            val mnem = line.mnemonic.trim().lowercase()
            val op = line.opStr.trim().lowercase()

            if (mnem == "ldr" || mnem == "ldrsw") {
                val parts = op.split(',').map { it.trim() }
                if (parts.isNotEmpty()) {
                    val destReg = parts[0]
                    if (areRegistersCompatible(destReg, branchReg)) {
                        val bracketStart = op.indexOf('[')
                        val bracketEnd = op.indexOf(']')
                        if (bracketStart != -1 && bracketEnd != -1 && bracketEnd > bracketStart) {
                            val inside = op.substring(bracketStart + 1, bracketEnd).trim()
                            val insideParts = inside.split(',').map { it.trim() }
                            if (insideParts.isNotEmpty()) {
                                baseReg = insideParts[0]
                                loadIdx = i
                                break
                            }
                        }
                    }
                }
            }
        }

        if (baseReg == null || loadIdx == -1) return null

        // Step 2: Trace backward to find how baseReg is computed (adrp + add or adr)
        var currentReg = baseReg
        var adrpVal: Long? = null
        var addVal = 0L

        for (i in (loadIdx - 1) downTo 0) {
            if (loadIdx - i > 15) break
            val line = disassembly[i]
            val mnem = line.mnemonic.trim().lowercase()
            val op = line.opStr.trim().lowercase()

            val parts = op.split(',').map { it.trim() }
            if (parts.isNotEmpty()) {
                val destReg = parts[0]
                if (destReg == currentReg) {
                    if (mnem == "add") {
                        if (parts.size >= 3) {
                            val srcReg = parts[1]
                            val immStr = parts[2]
                            val parsedImm = parseOffset(immStr)
                            if (parsedImm != null) {
                                addVal = parsedImm
                                currentReg = srcReg
                            }
                        }
                    } else if (mnem == "adrp") {
                        if (parts.size >= 2) {
                            val immStr = parts[1]
                            val parsedImm = parseOffset(immStr)
                            if (parsedImm != null) {
                                adrpVal = chooseBestEa(line.address, parsedImm)
                                break
                            }
                        }
                    } else if (mnem == "adr") {
                        if (parts.size >= 2) {
                            val immStr = parts[1]
                            val parsedImm = parseOffset(immStr)
                            if (parsedImm != null) {
                                adrpVal = parsedImm
                                break
                            }
                        }
                    }
                }
            }
        }

        if (adrpVal != null) {
            return adrpVal + addVal
        }
        return null
    }

    private fun chooseBestEa(pc: Long, adrpValue: Long): Long {
        if (adrpValue > 0x10000) {
            return adrpValue
        }
        val pageStart = pc and 4095.inv()
        return pageStart + adrpValue * 4096
    }

    private fun areRegistersCompatible(r1: String, r2: String): Boolean {
        val clean1 = r1.trim().lowercase()
        val clean2 = r2.trim().lowercase()
        if (clean1 == clean2) return true
        if (clean1.startsWith("w") && clean2.startsWith("x")) {
            return clean1.substring(1) == clean2.substring(1)
        }
        if (clean1.startsWith("x") && clean2.startsWith("w")) {
            return clean1.substring(1) == clean2.substring(1)
        }
        return false
    }

    private fun findX86TableBase(opStr: String): Long? {
        val startBracket = opStr.indexOf('[')
        val endBracket = opStr.indexOf(']')
        if (startBracket == -1 || endBracket == -1 || endBracket <= startBracket) return null
        val inside = opStr.substring(startBracket + 1, endBracket).trim()

        // Look for hex address (e.g., 0x401234)
        val hexMatch = Regex("0x([0-9a-fA-F]+)").find(inside)
        if (hexMatch != null) {
            return hexMatch.groupValues[1].toLongOrNull(16)
        }

        // Look for large decimal address
        val decMatch = Regex("\\b([0-9]{4,})\\b").find(inside)
        if (decMatch != null) {
            return decMatch.groupValues[1].toLongOrNull()
        }
        return null
    }

    private fun resolveTableTargets(
        tableBaseAddr: Long,
        buffer: ByteBuffer?,
        isLittleEndian: Boolean,
        sections: List<ElfParser.SectionInfo>,
        textStart: Long,
        textEnd: Long,
        is64Bit: Boolean
    ): List<Long> {
        if (buffer == null) return emptyList()
        val maxEntries = 512

        // Try Relative 32-bit offsets first (common in PIC ARM64/x86_64)
        val relativeTargets = mutableListOf<Long>()
        var isValidRelative = false
        try {
            val fileOffset = translateVaToOffset(tableBaseAddr, sections)
            if (fileOffset != null && fileOffset >= 0 && fileOffset + 4 <= buffer.capacity()) {
                val dup = buffer.duplicate()
                dup.order(if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
                dup.position(fileOffset)
                val firstOffset = dup.getInt().toLong()
                val firstTarget = tableBaseAddr + firstOffset
                if (firstTarget in textStart until textEnd) {
                    isValidRelative = true
                }
            }
        } catch (e: Exception) {
            // Ignore
        }

        if (isValidRelative) {
            val dup = buffer.duplicate()
            dup.order(if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
            var currentAddr = tableBaseAddr
            for (i in 0 until maxEntries) {
                val fileOffset = translateVaToOffset(currentAddr, sections) ?: break
                if (fileOffset < 0 || fileOffset + 4 > buffer.capacity()) break
                dup.position(fileOffset)
                val offsetVal = dup.getInt().toLong()
                val target = tableBaseAddr + offsetVal
                if (target in textStart until textEnd) {
                    relativeTargets.add(target)
                    currentAddr += 4
                } else {
                    break
                }
            }
            if (relativeTargets.isNotEmpty()) {
                return relativeTargets
            }
        }

        // Fallback: Absolute addresses
        val absoluteTargets = mutableListOf<Long>()
        val entrySize = if (is64Bit) 8 else 4
        val dup = buffer.duplicate()
        dup.order(if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
        var currentAddr = tableBaseAddr
        for (i in 0 until maxEntries) {
            val fileOffset = translateVaToOffset(currentAddr, sections) ?: break
            if (fileOffset < 0 || fileOffset + entrySize > buffer.capacity()) break
            dup.position(fileOffset)
            val target = if (is64Bit) {
                dup.getLong()
            } else {
                dup.getInt().toLong() and 0xFFFFFFFFL
            }
            if (target in textStart until textEnd) {
                absoluteTargets.add(target)
                currentAddr += entrySize
            } else {
                break
            }
        }

        return absoluteTargets
    }

    private fun translateVaToOffset(va: Long, sections: List<ElfParser.SectionInfo>): Int? {
        for (sec in sections) {
            if (va >= sec.startAddress && va < sec.startAddress + sec.size) {
                val offsetInSec = va - sec.startAddress
                val fileOffset = sec.fileOffset + offsetInSec
                return fileOffset.toInt()
            }
        }
        return null
    }

    private fun parseOffset(str: String): Long? {
        val clean = str.replace("#", "").replace("[", "").replace("]", "").trim().lowercase()
        val isNegative = clean.startsWith("-")
        val absoluteStr = if (isNegative) clean.substring(1).trim() else clean
        val value = if (absoluteStr.startsWith("0x")) {
            absoluteStr.substring(2).toLongOrNull(16)
        } else {
            absoluteStr.toLongOrNull(10)
        }
        return if (value != null) {
            if (isNegative) -value else value
        } else null
    }
}
