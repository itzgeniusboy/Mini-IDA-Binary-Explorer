package com.example

object XrefAnalyzer {
    
    // Pattern to match hexadecimal addresses in operand strings (e.g., 0x400080 or #0x400080)
    private val hexRegex = Regex("0x([0-9a-fA-F]+)")
    
    // Pattern to match decimal numbers
    private val decRegex = Regex("\\b([0-9]{4,})\\b") // Only match larger numbers to avoid register index / small offsets

    fun analyze(disassembly: List<DisassemblyLine>): List<XrefEntry> {
        if (disassembly.isEmpty()) return emptyList()
        
        val minAddr = disassembly.first().address
        val maxAddr = disassembly.last().address
        
        val xrefs = mutableListOf<XrefEntry>()
        
        for (line in disassembly) {
            val mnemonic = line.mnemonic.trim().lowercase()
            val opStr = line.opStr.trim()
            
            if (isBranchOrCall(mnemonic)) {
                // Determine branch type: "CALL" or "BRANCH"
                val type = if (isCall(mnemonic)) "CALL" else "BRANCH"
                
                // Try to parse direct address
                val targetAddr = extractTargetAddress(opStr)
                if (targetAddr != null) {
                    // Check if target is within .text section's range
                    if (targetAddr in minAddr..maxAddr) {
                        xrefs.add(XrefEntry(fromAddr = line.address, toAddr = targetAddr, type = type))
                    }
                }
            }
        }
        
        return xrefs
    }
    
    private fun isBranchOrCall(mnemonic: String): Boolean {
        // ARM / ARM64
        if (mnemonic == "b" || mnemonic == "bl" || mnemonic == "blx") return true
        if (mnemonic.startsWith("b.") || mnemonic.startsWith("b")) {
            // Check for conditional branch mnemonics like beq, bne, bge, etc.
            val conds = setOf("eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le", "al", "eqx", "nex")
            val suffix = mnemonic.removePrefix("b")
            if (conds.contains(suffix) || mnemonic.startsWith("b.")) return true
        }
        if (mnemonic == "cbz" || mnemonic == "cbnz" || mnemonic == "tbz" || mnemonic == "tbnz") return true

        // x86 / x86_64
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
        // Find first hex match
        val hexMatch = hexRegex.find(opStr)
        if (hexMatch != null) {
            return hexMatch.groupValues[1].toLongOrNull(16)
        }
        
        // If no hex match, check if it's an indirect register-only target
        // e.g. "x19", "r3", "rax", "eax"
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
        // Register matches like r0-r15, x0-x31, w0-w31, eax, ebx, ecx, edx, esp, ebp, esi, edi, rax, rbx, rcx, rdx, rsp, rbp, rsi, rdi, r8-r15
        val regRegex = Regex("^([rxw][0-9]+|e[a-d]x|r[a-d]x|e[sbi]p|r[sbi]p|e[sdi]i|r[sdi]i|r[0-9]+[d-w]?)$")
        return regRegex.matches(trimmed)
    }
}
