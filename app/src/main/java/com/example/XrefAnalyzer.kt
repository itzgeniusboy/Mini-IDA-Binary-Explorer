package com.example

import java.nio.ByteBuffer
import java.nio.ByteOrder

object XrefAnalyzer {
    
    // Pattern to match hexadecimal addresses in operand strings (e.g., 0x400080 or #0x400080)
    private val hexRegex = Regex("0x([0-9a-fA-F]+)")
    
    // Pattern to match decimal numbers
    private val decRegex = Regex("\\b([0-9]{4,})\\b") // Only match larger numbers to avoid register index / small offsets

    // Pattern to match RIP-relative addressing
    private val ripRegex = Regex("\\[rip\\s*([+-])\\s*0x([0-9a-fA-F]+)\\]")
    private val ripRegexDec = Regex("\\[rip\\s*([+-])\\s*([0-9]+)\\]")

    data class BaseAdrpInfo(
        val pc: Long,
        val value: Long
    )

    fun analyze(disassembly: List<DisassemblyLine>): List<XrefEntry> {
        return analyze(disassembly, emptyList(), emptyList(), null, true)
    }

    fun analyze(
        disassembly: List<DisassemblyLine>,
        knownStrings: List<ElfParser.ElfString>,
        sections: List<ElfParser.SectionInfo>,
        buffer: ByteBuffer?,
        isLittleEndian: Boolean
    ): List<XrefEntry> {
        if (disassembly.isEmpty()) return emptyList()
        
        val minAddr = disassembly.first().address
        val maxAddr = disassembly.last().address
        
        val xrefs = mutableListOf<XrefEntry>()
        val activeAdrp = mutableMapOf<String, BaseAdrpInfo>()
        
        for (line in disassembly) {
            val mnemonic = line.mnemonic.trim().lowercase()
            val opStr = line.opStr.trim()
            
            // --- 1. Existing Code Xref tracking ---
            if (isBranchOrCall(mnemonic)) {
                val type = if (isCall(mnemonic)) "CALL" else "BRANCH"
                val targetAddr = extractTargetAddress(opStr)
                if (targetAddr != null) {
                    if (targetAddr in minAddr..maxAddr) {
                        xrefs.add(XrefEntry(fromAddr = line.address, toAddr = targetAddr, type = type))
                    }
                }
            }
            
            // --- 2. ARM64: ADRP + ADD/LDR tracking ---
            if (mnemonic == "adrp") {
                val firstComma = opStr.indexOf(',')
                if (firstComma != -1) {
                    val destReg = opStr.substring(0, firstComma).trim().lowercase()
                    val immStr = opStr.substring(firstComma + 1).trim()
                    val parsedImm = parseOffset(immStr)
                    if (parsedImm != null) {
                        activeAdrp[destReg] = BaseAdrpInfo(line.address, parsedImm)
                    }
                }
            } else if (mnemonic == "add") {
                val parts = opStr.split(',').map { it.trim().lowercase() }
                if (parts.size >= 3) {
                    val destReg = parts[0]
                    val srcReg = parts[1]
                    val immStr = parts[2]
                    val baseInfo = activeAdrp[srcReg]
                    if (baseInfo != null) {
                        val offset = parseOffset(immStr)
                        if (offset != null) {
                            val resolvedEa = chooseBestEa(baseInfo.pc, baseInfo.value, offset, knownStrings, sections)
                            if (resolvedEa != null) {
                                val xrefType = if (isStringAddress(resolvedEa, knownStrings)) "string_ref" else "data_ref"
                                xrefs.add(XrefEntry(fromAddr = line.address, toAddr = resolvedEa, type = xrefType))
                            }
                        }
                    }
                    if (destReg != srcReg) {
                        activeAdrp.remove(destReg)
                    }
                }
            } else if (mnemonic.startsWith("ldr") || mnemonic.startsWith("str")) {
                val firstComma = opStr.indexOf(',')
                if (firstComma != -1) {
                    val destReg = opStr.substring(0, firstComma).trim().lowercase()
                    val bracketStart = opStr.indexOf('[')
                    val bracketEnd = opStr.indexOf(']')
                    if (bracketStart != -1 && bracketEnd != -1 && bracketEnd > bracketStart) {
                        val inside = opStr.substring(bracketStart + 1, bracketEnd).trim().lowercase()
                        val parts = inside.split(',').map { it.trim() }
                        if (parts.isNotEmpty()) {
                            val srcReg = parts[0]
                            val baseInfo = activeAdrp[srcReg]
                            if (baseInfo != null) {
                                val offset = if (parts.size >= 2) parseOffset(parts[1]) ?: 0L else 0L
                                val resolvedEa = chooseBestEa(baseInfo.pc, baseInfo.value, offset, knownStrings, sections)
                                if (resolvedEa != null) {
                                    val xrefType = if (isStringAddress(resolvedEa, knownStrings)) "string_ref" else "data_ref"
                                    xrefs.add(XrefEntry(fromAddr = line.address, toAddr = resolvedEa, type = xrefType))
                                }
                            }
                        }
                    }
                    activeAdrp.remove(destReg)
                }
            } else {
                val firstComma = opStr.indexOf(',')
                if (firstComma != -1) {
                    val destReg = opStr.substring(0, firstComma).trim().lowercase()
                    if (destReg.isNotEmpty() && !destReg.contains(" ")) {
                        activeAdrp.remove(destReg)
                    }
                }
            }

            // --- 3. ARM32: LDR with PC-relative addressing (literal pools) ---
            if (mnemonic.startsWith("ldr")) {
                val bracketStart = opStr.indexOf('[')
                val bracketEnd = opStr.indexOf(']')
                if (bracketStart != -1 && bracketEnd != -1 && bracketEnd > bracketStart) {
                    val inside = opStr.substring(bracketStart + 1, bracketEnd).trim().lowercase()
                    val parts = inside.split(',').map { it.trim() }
                    if (parts.isNotEmpty() && parts[0] == "pc") {
                        val offset = if (parts.size >= 2) parseOffset(parts[1]) ?: 0L else 0L
                        val pcCandidates = listOf(line.address + 8, line.address + 4)
                        for (pc in pcCandidates) {
                            val literalPoolVa = pc + offset
                            if (buffer != null) {
                                val fileOffset = translateVaToOffset(literalPoolVa, sections)
                                if (fileOffset != null && fileOffset >= 0 && fileOffset + 4 <= buffer.capacity()) {
                                    val dup = buffer.duplicate()
                                    dup.order(if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)
                                    val loadedVal = dup.getInt(fileOffset).toLong() and 0xFFFFFFFFL
                                    if (isStringAddress(loadedVal, knownStrings) || isDataSectionAddress(loadedVal, sections)) {
                                        val xrefType = if (isStringAddress(loadedVal, knownStrings)) "string_ref" else "data_ref"
                                        xrefs.add(XrefEntry(fromAddr = line.address, toAddr = loadedVal, type = xrefType))
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // --- 4. x86 / x86_64: RIP-relative addressing ---
            if (opStr.contains("[rip", ignoreCase = true)) {
                val ripMatch = ripRegex.find(opStr) ?: ripRegexDec.find(opStr)
                if (ripMatch != null) {
                    val sign = ripMatch.groupValues[1]
                    val offsetStr = ripMatch.groupValues[2]
                    val isHex = ripMatch.value.contains("0x")
                    val parsedOffset = if (isHex) offsetStr.toLongOrNull(16) else offsetStr.toLongOrNull(10)
                    if (parsedOffset != null) {
                        val offset = if (sign == "-") -parsedOffset else parsedOffset
                        val instrLen = line.bytesHex.length / 2
                        val rip = line.address + instrLen
                        val effectiveAddress = rip + offset
                        if (isStringAddress(effectiveAddress, knownStrings) || isDataSectionAddress(effectiveAddress, sections)) {
                            val xrefType = if (isStringAddress(effectiveAddress, knownStrings)) "string_ref" else "data_ref"
                            xrefs.add(XrefEntry(fromAddr = line.address, toAddr = effectiveAddress, type = xrefType))
                        }
                    }
                }
            }
        }
        
        return xrefs
    }

    private fun isBranchOrCall(mnemonic: String): Boolean {
        if (mnemonic == "b" || mnemonic == "bl" || mnemonic == "blx") return true
        if (mnemonic.startsWith("b.") || mnemonic.startsWith("b")) {
            val conds = setOf("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "eqx", "nex")
            val suffix = mnemonic.removePrefix("b")
            if (conds.contains(suffix) || mnemonic.startsWith("b.")) return true
        }
        if (mnemonic == "cbz" || mnemonic == "cbnz" || mnemonic == "tbz" || mnemonic == "tbnz") return true

        if (mnemonic == "call" || mnemonic == "jmp") return true
        if (mnemonic.startsWith("j")) {
            val x86conds = setOf("e", "ne", "z", "nz", "g", "ge", "l", "le", "a", "ae", "b", "be", "c", "nc", "o", "no", "s", "ns", "p", "np", "pe", "po", "cxz", "ecxz", "rcxz")
            val suffix = mnemonic.removePrefix("j")
            if (x86conds.contains(suffix)) return true
        }
        
        return false
    }
    
    private fun isCall(mnemonic: String): Boolean {
        return mnemonic == "bl" || mnemonic == "blx" || mnemonic == "call"
    }
    
    fun extractTargetAddress(opStr: String): Long? {
        val hexMatch = hexRegex.find(opStr)
        if (hexMatch != null) {
            return hexMatch.groupValues[1].toLongOrNull(16)
        }
        
        if (isIndirectRegister(opStr)) {
            return null
        }
        
        val decMatch = decRegex.find(opStr)
        if (decMatch != null) {
            return decMatch.groupValues[1].toLongOrNull(10)
        }
        
        return null
    }

    private fun isIndirectRegister(opStr: String): Boolean {
        val trimmed = opStr.trim().lowercase()
        val regRegex = Regex("^([rxw][0-9]+|e[a-d]x|r[a-d]x|e[sbi]p|r[sbi]p|e[sdi]i|r[sdi]i|r[0-9]+[d-w]?)$")
        return regRegex.matches(trimmed)
    }

    private fun isStringAddress(addr: Long, knownStrings: List<ElfParser.ElfString>): Boolean {
        for (str in knownStrings) {
            val start = str.offset.removePrefix("0x").toLongOrNull(16) ?: continue
            if (addr >= start && addr < start + str.length) {
                return true
            }
        }
        return false
    }

    private fun isDataSectionAddress(addr: Long, sections: List<ElfParser.SectionInfo>): Boolean {
        for (sec in sections) {
            val name = sec.name.lowercase()
            if (name == ".data" || name == ".bss" || name == ".rodata" || name == ".got" || name == ".plt" || name == ".data.rel.ro" || name == ".tbss" || name == ".tdata") {
                if (addr >= sec.startAddress && addr < sec.startAddress + sec.size) {
                    return true
                }
            }
        }
        return false
    }

    private fun chooseBestEa(
        pc: Long,
        adrpValue: Long,
        offset: Long,
        knownStrings: List<ElfParser.ElfString>,
        sections: List<ElfParser.SectionInfo>
    ): Long? {
        val eaAbsolute = adrpValue + offset
        val eaRelative = (pc and 4095.inv()) + adrpValue * 4096 + offset
        val eaRelativeOffset = (pc and 4095.inv()) + adrpValue + offset
        
        val candidates = listOf(eaAbsolute, eaRelative, eaRelativeOffset)
        
        for (ea in candidates) {
            if (isStringAddress(ea, knownStrings)) {
                return ea
            }
        }
        
        for (ea in candidates) {
            if (isDataSectionAddress(ea, sections)) {
                return ea
            }
        }
        
        return null
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
