package com.example

import android.content.Context
import android.util.Log
import org.json.JSONArray
import java.io.InputStreamReader

enum class ElfArch {
    ARM32,
    ARM64,
    X86,
    X86_64,
    UNKNOWN;

    companion object {
        fun fromMachineVal(machineVal: Int): ElfArch {
            return when (machineVal) {
                3 -> X86
                40 -> ARM32
                62 -> X86_64
                183 -> ARM64
                else -> UNKNOWN
            }
        }
    }
}

data class SignatureMatch(
    val functionName: String,
    val confidence: Float,
    val signatureSource: String
)

data class Signature(
    val name: String,
    val arch: ElfArch,
    val pattern: ByteArray,
    val mask: ByteArray,
    val source: String
)

object SignatureMatcher {
    private const val TAG = "SignatureMatcher"
    private val signatures = mutableListOf<Signature>()
    private var isLoaded = false

    // In-memory cache of suggestions mapped by address
    private val suggestedMatches = mutableMapOf<Long, SignatureMatch>()

    fun addSuggestion(address: Long, match: SignatureMatch) {
        synchronized(suggestedMatches) {
            suggestedMatches[address] = match
        }
    }

    fun getSuggestion(address: Long): SignatureMatch? {
        synchronized(suggestedMatches) {
            return suggestedMatches[address]
        }
    }

    fun removeSuggestion(address: Long) {
        synchronized(suggestedMatches) {
            suggestedMatches.remove(address)
        }
    }

    fun clear() {
        synchronized(suggestedMatches) {
            suggestedMatches.clear()
        }
    }

    fun loadSignatures(context: Context) {
        if (isLoaded) return
        synchronized(this) {
            if (isLoaded) return
            try {
                val inputStream = context.assets.open("signatures.json")
                val reader = InputStreamReader(inputStream)
                val jsonStr = reader.readText()
                reader.close()

                val jsonArray = JSONArray(jsonStr)
                for (i in 0 until jsonArray.length()) {
                    val obj = jsonArray.getJSONObject(i)
                    val name = obj.getString("name")
                    val archStr = obj.getString("arch")
                    val arch = try {
                        ElfArch.valueOf(archStr.uppercase())
                    } catch (e: Exception) {
                        ElfArch.UNKNOWN
                    }
                    val patternHex = obj.getString("pattern").replace("\\s".toRegex(), "")
                    val maskHex = obj.getString("mask").replace("\\s".toRegex(), "")
                    val source = obj.optString("source", "builtin")

                    if (patternHex.length != maskHex.length || patternHex.isEmpty()) {
                        Log.w(TAG, "Invalid signature $name: pattern and mask lengths must match and be non-empty")
                        continue
                    }

                    val patternBytes = hexToBytes(patternHex)
                    val maskBytes = hexToBytes(maskHex)

                    signatures.add(Signature(name, arch, patternBytes, maskBytes, source))
                }
                isLoaded = true
                Log.d(TAG, "Loaded ${signatures.size} signatures successfully")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load signatures from assets", e)
            }
        }
    }

    fun matchFunction(functionBytes: ByteArray, arch: ElfArch): SignatureMatch? {
        if (functionBytes.isEmpty() || arch == ElfArch.UNKNOWN) return null

        var bestMatch: Signature? = null
        var bestConfidence = 0.0f

        val archSigs = signatures.filter { it.arch == arch }

        for (sig in archSigs) {
            val sigLen = sig.pattern.size
            if (functionBytes.size < sigLen) continue

            var matchCount = 0
            var matched = true

            for (i in 0 until sigLen) {
                val fByte = functionBytes[i].toInt() and 0xFF
                val pByte = sig.pattern[i].toInt() and 0xFF
                val mByte = sig.mask[i].toInt() and 0xFF

                if ((fByte and mByte) == (pByte and mByte)) {
                    if (mByte == 0xFF) {
                        matchCount++
                    }
                } else {
                    matched = false
                    break
                }
            }

            if (matched) {
                // Calculate confidence as fraction of matching bytes
                val confidence = if (sigLen > 0) matchCount.toFloat() / sigLen.toFloat() else 0f
                if (confidence >= 0.7f && confidence > bestConfidence) {
                    bestConfidence = confidence
                    bestMatch = sig
                }
            }
        }

        return if (bestMatch != null) {
            SignatureMatch(
                functionName = bestMatch.name,
                confidence = bestConfidence,
                signatureSource = bestMatch.source
            )
        } else {
            null
        }
    }

    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            data[i / 2] = ((Character.digit(hex[i], 16) shl 4) + Character.digit(hex[i + 1], 16)).toByte()
            i += 2
        }
        return data
    }
}
