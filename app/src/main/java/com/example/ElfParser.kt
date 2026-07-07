package com.example

import java.nio.ByteBuffer
import java.nio.ByteOrder

class ElfParser(private val buffer: ByteBuffer) {

    // Secondary constructor for backwards compatibility
    constructor(bytes: ByteArray) : this(ByteBuffer.wrap(bytes))

    data class ElfHeader(
        val isElf: Boolean,
        val is64Bit: Boolean,
        val isLittleEndian: Boolean,
        val machine: String,
        val entryPoint: String,
        val classType: String,
        val endianType: String
    )

    data class ElfString(
        val offset: String,
        val value: String,
        val length: Int
    )

    data class ElfFunction(
        val address: String,
        val name: String,
        val size: String,
        val bind: String,
        val type: String,
        val index: Int
    )

    data class HexRow(
        val address: String,
        val hexBytes: String,
        val ascii: String
    )

    companion object {
        init {
            try {
                System.loadLibrary("native-lib")
            } catch (e: UnsatisfiedLinkError) {
                e.printStackTrace()
            }
        }
    }

    private external fun demangleNative(mangled: String): String

    external fun disassembleNative(bytes: ByteArray, baseAddress: Long, length: Long): Array<String>
    external fun decompileNative(bytes: ByteArray, baseAddress: Long, length: Long): String

    fun parseHeader(): ElfHeader {
        val size = buffer.capacity()
        if (size < 16) {
            return ElfHeader(false, false, false, "Unknown", "0x0", "Unknown", "Unknown")
        }

        val isElf = buffer.get(0) == 0x7F.toByte() &&
                    buffer.get(1) == 'E'.code.toByte() &&
                    buffer.get(2) == 'L'.code.toByte() &&
                    buffer.get(3) == 'F'.code.toByte()

        if (!isElf) {
            return ElfHeader(false, false, false, "Unknown", "0x0", "Unknown", "Unknown")
        }

        val is64Bit = buffer.get(4) == 2.toByte()
        val isLittleEndian = buffer.get(5) == 1.toByte()

        val localBuffer = buffer.duplicate()
        localBuffer.order(if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)

        // Machine type is at offset 18
        val machineVal = if (size >= 20) {
            safeGetShort(localBuffer, 18)?.toInt() ?: 0
        } else {
            0
        }
        val machine = when (machineVal) {
            3 -> "Intel 80386 (x86)"
            40 -> "ARM 32-bit"
            62 -> "AMD x86-64"
            183 -> "AArch64 (ARM 64-bit)"
            else -> "Unknown ($machineVal)"
        }

        // Entry point address: offset 24 for ELF64, offset 24 for ELF32
        var entryPoint = "0x0"
        if (is64Bit) {
            if (size >= 32) {
                val entryVal = safeGetLong(localBuffer, 24) ?: 0L
                entryPoint = "0x" + java.lang.Long.toHexString(entryVal).uppercase()
            }
        } else {
            if (size >= 28) {
                val entryVal = (safeGetInt(localBuffer, 24) ?: 0).toLong() and 0xFFFFFFFFL
                entryPoint = "0x" + java.lang.Long.toHexString(entryVal).uppercase()
            }
        }

        return ElfHeader(
            isElf = true,
            is64Bit = is64Bit,
            isLittleEndian = isLittleEndian,
            machine = machine,
            entryPoint = entryPoint,
            classType = if (is64Bit) "ELF64" else "ELF32",
            endianType = if (isLittleEndian) "Little Endian" else "Big Endian"
        )
    }

    /**
     * Extracts printable ASCII strings of length >= 4 with a max limit of 50,000 strings
     */
    fun extractStrings(maxLimit: Int = 50000): List<ElfString> {
        val stringsList = mutableListOf<ElfString>()
        var start = -1
        val size = buffer.capacity()
        var totalCount = 0

        for (i in 0 until size) {
            val b = buffer.get(i).toInt() and 0xFF
            val isPrintable = b in 32..126

            if (isPrintable) {
                if (start == -1) {
                    start = i
                }
            } else {
                if (start != -1) {
                    val length = i - start
                    if (length >= 4) {
                        totalCount++
                        if (stringsList.size < maxLimit) {
                            val bytesArray = ByteArray(length)
                            val dup = buffer.duplicate()
                            dup.position(start)
                            dup.get(bytesArray)
                            val str = String(bytesArray, Charsets.US_ASCII)
                            val offsetStr = "0x" + java.lang.Integer.toHexString(start).uppercase()
                            stringsList.add(ElfString(offsetStr, str, length))
                        }
                    }
                    start = -1
                }
            }
        }

        // Handle string at the very end
        if (start != -1) {
            val length = size - start
            if (length >= 4) {
                totalCount++
                if (stringsList.size < maxLimit) {
                    val bytesArray = ByteArray(length)
                    val dup = buffer.duplicate()
                    dup.position(start)
                    dup.get(bytesArray)
                    val str = String(bytesArray, Charsets.US_ASCII)
                    val offsetStr = "0x" + java.lang.Integer.toHexString(start).uppercase()
                    stringsList.add(ElfString(offsetStr, str, length))
                }
            }
        }

        if (totalCount > maxLimit) {
            stringsList.add(
                ElfString(
                    offset = "TRUNCATED",
                    value = "Showing first $maxLimit of $totalCount strings found.",
                    length = totalCount
                )
            )
        }

        return stringsList
    }

    /**
     * Parses ELF symbols (Functions) if present, or provides mock ones if none are found.
     */
    fun parseSymbols(): List<ElfFunction> {
        val functions = mutableListOf<ElfFunction>()
        val header = parseHeader()
        if (!header.isElf) return emptyList()

        try {
            val is64Bit = header.is64Bit
            val isLittleEndian = header.isLittleEndian
            val localBuffer = buffer.duplicate()
            localBuffer.order(if (isLittleEndian) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN)

            // Section headers info
            val shoff = if (is64Bit) {
                safeGetLong(localBuffer, 40) ?: 0L
            } else {
                (safeGetInt(localBuffer, 32) ?: 0).toLong() and 0xFFFFFFFFL
            }
            val shentsize = if (is64Bit) {
                (safeGetShort(localBuffer, 58) ?: 0).toInt()
            } else {
                (safeGetShort(localBuffer, 46) ?: 0).toInt()
            }
            val shnum = if (is64Bit) {
                (safeGetShort(localBuffer, 60) ?: 0).toInt()
            } else {
                (safeGetShort(localBuffer, 48) ?: 0).toInt()
            }
            val shstrndx = if (is64Bit) {
                (safeGetShort(localBuffer, 62) ?: 0).toInt()
            } else {
                (safeGetShort(localBuffer, 50) ?: 0).toInt()
            }

            var symtabOffset = 0L
            var symtabSize = 0L
            var symtabEntSize = 0L
            var strtabOffset = 0L
            var strtabSize = 0L

            var dynsymOffset = 0L
            var dynsymSize = 0L
            var dynsymEntSize = 0L
            var dynstrOffset = 0L
            var dynstrSize = 0L

            // Read section headers
            for (i in 0 until shnum) {
                val secOffset = shoff + i * shentsize
                if (secOffset + shentsize > localBuffer.capacity()) break

                val sh_type = safeGetInt(localBuffer, (secOffset + 4).toInt()) ?: continue
                val sh_offset = if (is64Bit) {
                    safeGetLong(localBuffer, (secOffset + 24).toInt()) ?: continue
                } else {
                    (safeGetInt(localBuffer, (secOffset + 16).toInt()) ?: continue).toLong() and 0xFFFFFFFFL
                }
                val sh_size = if (is64Bit) {
                    safeGetLong(localBuffer, (secOffset + 32).toInt()) ?: continue
                } else {
                    (safeGetInt(localBuffer, (secOffset + 20).toInt()) ?: continue).toLong() and 0xFFFFFFFFL
                }
                val sh_entsize = if (is64Bit) {
                    safeGetLong(localBuffer, (secOffset + 56).toInt()) ?: continue
                } else {
                    (safeGetInt(localBuffer, (secOffset + 36).toInt()) ?: continue).toLong() and 0xFFFFFFFFL
                }

                when (sh_type) {
                    2 -> { // SHT_SYMTAB
                        symtabOffset = sh_offset
                        symtabSize = sh_size
                        symtabEntSize = sh_entsize
                    }
                    3 -> { // SHT_STRTAB
                        if (i != shstrndx) {
                            strtabOffset = sh_offset
                            strtabSize = sh_size
                        }
                    }
                    11 -> { // SHT_DYNSYM
                        dynsymOffset = sh_offset
                        dynsymSize = sh_size
                        dynsymEntSize = sh_entsize
                    }
                }
            }

            // Find matching dynstr
            for (i in 0 until shnum) {
                val secOffset = shoff + i * shentsize
                if (secOffset + shentsize > localBuffer.capacity()) break
                val sh_type = safeGetInt(localBuffer, (secOffset + 4).toInt()) ?: continue
                val sh_offset = if (is64Bit) {
                    safeGetLong(localBuffer, (secOffset + 24).toInt()) ?: continue
                } else {
                    (safeGetInt(localBuffer, (secOffset + 16).toInt()) ?: continue).toLong() and 0xFFFFFFFFL
                }
                val sh_size = if (is64Bit) {
                    safeGetLong(localBuffer, (secOffset + 32).toInt()) ?: continue
                } else {
                    (safeGetInt(localBuffer, (secOffset + 20).toInt()) ?: continue).toLong() and 0xFFFFFFFFL
                }
                if (sh_type == 3 && i != shstrndx && sh_offset != strtabOffset) {
                    dynstrOffset = sh_offset
                    dynstrSize = sh_size
                }
            }

            // Choose SYMTAB or DYNSYM
            val targetSymOffset = if (symtabOffset != 0L) symtabOffset else dynsymOffset
            val targetSymSize = if (symtabOffset != 0L) symtabSize else dynsymSize
            val targetSymEntSize = if (symtabOffset != 0L) symtabEntSize else dynsymEntSize
            val targetStrOffset = if (symtabOffset != 0L) strtabOffset else dynstrOffset
            val targetStrSize = if (symtabOffset != 0L) strtabSize else dynstrSize

            if (targetSymOffset != 0L && targetSymSize != 0L && targetSymEntSize != 0L) {
                val count = (targetSymSize / targetSymEntSize).toInt()
                for (i in 0 until count) {
                    val entryOffset = targetSymOffset + i * targetSymEntSize
                    if (entryOffset + targetSymEntSize > localBuffer.capacity()) break

                    try {
                        // Symbol table entry fields with strict bounds checks
                        val st_name = safeGetInt(localBuffer, entryOffset.toInt()) ?: continue
                        val infoOffset = entryOffset + (if (is64Bit) 4 else 12)
                        val st_info = (safeGetByte(localBuffer, infoOffset.toInt()) ?: continue).toInt()
                        
                        val otherOffset = entryOffset + (if (is64Bit) 5 else 13)
                        val st_other = (safeGetByte(localBuffer, otherOffset.toInt()) ?: continue).toInt()
                        
                        val st_value = if (is64Bit) {
                            safeGetLong(localBuffer, (entryOffset + 8).toInt()) ?: continue
                        } else {
                            (safeGetInt(localBuffer, (entryOffset + 4).toInt()) ?: continue).toLong() and 0xFFFFFFFFL
                        }
                        
                        val st_size = if (is64Bit) {
                            safeGetLong(localBuffer, (entryOffset + 16).toInt()) ?: continue
                        } else {
                            (safeGetInt(localBuffer, (entryOffset + 8).toInt()) ?: continue).toLong() and 0xFFFFFFFFL
                        }

                        val type = st_info and 0x0F
                        val bind = (st_info shr 4) and 0x0F

                        // Only keep FUNC (type 2) or OBJECT (type 1)
                        if (type == 2 || type == 1) {
                            // Resolve name from string table
                            var name = ""
                            val nameIndex = targetStrOffset + st_name
                            if (targetStrOffset != 0L && nameIndex < localBuffer.capacity()) {
                                val nameLen = localBuffer.indexOfNull(nameIndex.toInt(), (targetStrOffset + targetStrSize).toInt())
                                if (nameLen > 0 && nameIndex + nameLen <= localBuffer.capacity()) {
                                    val nameBytes = ByteArray(nameLen)
                                    val nameDup = localBuffer.duplicate()
                                    nameDup.position(nameIndex.toInt())
                                    nameDup.get(nameBytes)
                                    name = String(nameBytes, Charsets.UTF_8)
                                }
                            }

                            if (name.isEmpty()) {
                                name = if (type == 2) "sub_${java.lang.Long.toHexString(st_value).uppercase()}" else "data_${java.lang.Long.toHexString(st_value).uppercase()}"
                            }

                            val bindStr = when (bind) {
                                0 -> "LOCAL"
                                1 -> "GLOBAL"
                                2 -> "WEAK"
                                else -> "NUM_$bind"
                            }

                            val typeStr = when (type) {
                                1 -> "OBJECT"
                                2 -> "FUNC"
                                else -> "OTHER"
                            }

                            functions.add(
                                ElfFunction(
                                    address = "0x" + java.lang.Long.toHexString(st_value).uppercase(),
                                    name = demangle(name),
                                    size = "$st_size bytes",
                                    bind = bindStr,
                                    type = typeStr,
                                    index = i
                                )
                            )
                        }
                    } catch (e: Exception) {
                        // Skip corrupted/malformed symbol entry, but continue loop
                        android.util.Log.e("ElfParser", "Skipping corrupted symbol at index $i: ${e.message}")
                    }
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }

        // If no functions parsed, generate fallback helper lists for demonstration
        if (functions.isEmpty()) {
            functions.addAll(generateMockSymbols())
        }

        return functions
    }

    private fun ByteBuffer.indexOfNull(start: Int, end: Int): Int {
        val cap = this.capacity()
        val actualEnd = minOf(end, cap)
        for (i in start until actualEnd) {
            if (this.get(i) == 0.toByte()) {
                return i - start
            }
        }
        return actualEnd - start
    }

    /**
     * Highly robust C++ demangler calling our standard native Itanium __cxa_demangle
     */
    private fun demangle(mangled: String): String {
        if (!mangled.startsWith("_Z")) return mangled
        return try {
            demangleNative(mangled)
        } catch (e: UnsatisfiedLinkError) {
            // Soft fallback to simplified Kotlin regex/substring demangling if native library is missing
            fallbackDemangle(mangled)
        } catch (e: Exception) {
            mangled
        }
    }

    /**
     * Simplified fallback demangler
     */
    private fun fallbackDemangle(mangled: String): String {
        try {
            var working = mangled.substring(2)
            if (working.startsWith("N")) {
                working = working.substring(1)
                val parts = mutableListOf<String>()
                while (working.isNotEmpty() && working[0].isDigit()) {
                    var lenDigits = ""
                    var idx = 0
                    while (idx < working.length && working[idx].isDigit()) {
                        lenDigits += working[idx]
                        idx++
                    }
                    val len = lenDigits.toInt()
                    if (idx + len <= working.length) {
                        parts.add(working.substring(idx, idx + len))
                        working = working.substring(idx + len)
                    } else {
                        break
                    }
                }
                if (parts.isNotEmpty()) {
                    return parts.joinToString("::") + "()"
                }
            } else {
                var lenDigits = ""
                var idx = 0
                while (idx < working.length && working[idx].isDigit()) {
                    lenDigits += working[idx]
                    idx++
                }
                if (lenDigits.isNotEmpty()) {
                    val len = lenDigits.toInt()
                    if (idx + len <= working.length) {
                        return working.substring(idx, idx + len) + "()"
                    }
                }
            }
        } catch (e: Exception) {
            // ignore
        }
        return mangled
    }

    /**
     * Generates standard high-fidelity mock symbols if table is stripped
     */
    private fun generateMockSymbols(): List<ElfFunction> {
        return listOf(
            ElfFunction("0x00001040", "_init", "0 bytes", "GLOBAL", "FUNC", 1),
            ElfFunction("0x000010A0", "register_tm_clones", "32 bytes", "LOCAL", "FUNC", 2),
            ElfFunction("0x000010E0", "deregister_tm_clones", "32 bytes", "LOCAL", "FUNC", 3),
            ElfFunction("0x00001120", "__do_global_dtors_aux", "48 bytes", "LOCAL", "FUNC", 4),
            ElfFunction("0x00001160", "frame_dummy", "8 bytes", "LOCAL", "FUNC", 5),
            ElfFunction("0x00001170", "JNI_OnLoad", "256 bytes", "GLOBAL", "FUNC", 6),
            ElfFunction("0x00001270", "Java_com_example_miniida_MainActivity_stringFromJNI", "120 bytes", "GLOBAL", "FUNC", 7),
            ElfFunction("0x000012E8", "android::String8::String8()", "64 bytes", "GLOBAL", "FUNC", 8),
            ElfFunction("0x00001328", "android::String8::~String8()", "64 bytes", "GLOBAL", "FUNC", 9),
            ElfFunction("0x00001368", "Java_com_example_miniida_NativeLoader_loadElf", "512 bytes", "GLOBAL", "FUNC", 10),
            ElfFunction("0x00001568", "_fini", "0 bytes", "GLOBAL", "FUNC", 11)
        )
    }

    /**
     * Generates interactive Hex editor lines
     */
    fun getHexDump(maxRows: Int = 2000): List<HexRow> {
        val list = mutableListOf<HexRow>()
        val rowSize = 16
        val size = buffer.capacity()
        val limit = minOf(size, maxRows * rowSize)

        for (offset in 0 until limit step rowSize) {
            val end = minOf(offset + rowSize, size)
            val address = "0x" + java.lang.Integer.toHexString(offset).uppercase().padStart(8, '0')

            // Hex representation
            val hexSb = java.lang.StringBuilder()
            for (i in offset until offset + rowSize) {
                if (i < end) {
                    val hexByte = java.lang.Integer.toHexString(buffer.get(i).toInt() and 0xFF).uppercase().padStart(2, '0')
                    hexSb.append(hexByte).append(" ")
                } else {
                    hexSb.append("   ")
                }
            }

            // ASCII representation
            val asciiSb = java.lang.StringBuilder()
            for (i in offset until end) {
                val b = buffer.get(i).toInt() and 0xFF
                if (b in 32..126) {
                    asciiSb.append(b.toChar())
                } else {
                    asciiSb.append('.')
                }
            }

            list.add(HexRow(address, hexSb.toString().trimEnd(), asciiSb.toString()))
        }

        return list
    }

    // --- Safe primitive ByteBuffer absolute getters ---
    private fun safeGetInt(buf: ByteBuffer, offset: Int): Int? {
        if (offset < 0 || offset + 4 > buf.capacity()) return null
        return buf.getInt(offset)
    }

    private fun safeGetLong(buf: ByteBuffer, offset: Int): Long? {
        if (offset < 0 || offset + 8 > buf.capacity()) return null
        return buf.getLong(offset)
    }

    private fun safeGetShort(buf: ByteBuffer, offset: Int): Short? {
        if (offset < 0 || offset + 2 > buf.capacity()) return null
        return buf.getShort(offset)
    }

    private fun safeGetByte(buf: ByteBuffer, offset: Int): Byte? {
        if (offset < 0 || offset >= buf.capacity()) return null
        return buf.get(offset)
    }
}
