package com.example

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import java.util.Locale

data class SymbolResult(val name: String, val address: Long, val demangled: String?)
data class StringResult(val text: String, val address: Long)
data class AddressResult(val address: Long)

data class SearchResults(
    val symbols: List<SymbolResult>,
    val strings: List<StringResult>,
    val address: AddressResult?
)

object SearchEngine {

    suspend fun search(
        query: String,
        functions: List<ElfParser.ElfFunction>,
        strings: List<ElfParser.ElfString>,
        disassembly: List<DisassemblyLine>
    ): SearchResults = coroutineScope {
        val trimmedQuery = query.trim()
        if (trimmedQuery.isEmpty()) {
            return@coroutineScope SearchResults(emptyList(), emptyList(), null)
        }

        // Run search calls in parallel using async on Dispatchers.Default
        val symbolsDeferred = async(Dispatchers.Default) {
            searchSymbols(trimmedQuery, functions)
        }
        val stringsDeferred = async(Dispatchers.Default) {
            searchStrings(trimmedQuery, strings)
        }
        val addressDeferred = async(Dispatchers.Default) {
            searchAddress(trimmedQuery, disassembly)
        }

        SearchResults(
            symbols = symbolsDeferred.await(),
            strings = stringsDeferred.await(),
            address = addressDeferred.await()
        )
    }

    private fun searchSymbols(query: String, functions: List<ElfParser.ElfFunction>): List<SymbolResult> {
        val results = mutableListOf<SymbolResult>()
        val lowercaseQuery = query.lowercase(Locale.ROOT)

        for (fn in functions) {
            val nameLower = fn.name.lowercase(Locale.ROOT)
            if (nameLower.contains(lowercaseQuery)) {
                val addressLong = fn.address.removePrefix("0x").toLongOrNull(16) ?: 0L
                results.add(SymbolResult(fn.name, addressLong, null))
            }
        }

        // Sort by relevance: exact match > starts-with > contains
        return results.sortedWith { o1, o2 ->
            val name1 = o1.name.lowercase(Locale.ROOT)
            val name2 = o2.name.lowercase(Locale.ROOT)
            
            val isExact1 = name1 == lowercaseQuery
            val isExact2 = name2 == lowercaseQuery
            if (isExact1 && !isExact2) return@sortedWith -1
            if (!isExact1 && isExact2) return@sortedWith 1

            val starts1 = name1.startsWith(lowercaseQuery)
            val starts2 = name2.startsWith(lowercaseQuery)
            if (starts1 && !starts2) return@sortedWith -1
            if (!starts1 && starts2) return@sortedWith 1

            o1.name.compareTo(o2.name)
        }.take(200)
    }

    private fun searchStrings(query: String, strings: List<ElfParser.ElfString>): List<StringResult> {
        val results = mutableListOf<StringResult>()
        val lowercaseQuery = query.lowercase(Locale.ROOT)

        for (str in strings) {
            val textLower = str.value.lowercase(Locale.ROOT)
            if (textLower.contains(lowercaseQuery)) {
                val addressLong = str.offset.removePrefix("0x").toLongOrNull(16) ?: 0L
                results.add(StringResult(str.value, addressLong))
            }
        }

        // Sort by relevance: exact match > starts-with > contains
        return results.sortedWith { o1, o2 ->
            val text1 = o1.text.lowercase(Locale.ROOT)
            val text2 = o2.text.lowercase(Locale.ROOT)

            val isExact1 = text1 == lowercaseQuery
            val isExact2 = text2 == lowercaseQuery
            if (isExact1 && !isExact2) return@sortedWith -1
            if (!isExact1 && isExact2) return@sortedWith 1

            val starts1 = text1.startsWith(lowercaseQuery)
            val starts2 = text2.startsWith(lowercaseQuery)
            if (starts1 && !starts2) return@sortedWith -1
            if (!starts1 && starts2) return@sortedWith 1

            o1.text.compareTo(o2.text)
        }.take(200)
    }

    private fun searchAddress(query: String, disassembly: List<DisassemblyLine>): AddressResult? {
        if (disassembly.isEmpty()) return null

        val cleanQuery = query.removePrefix("0x").removePrefix("0X")
        val parsedAddr = cleanQuery.toLongOrNull(16) ?: return null

        val minAddr = disassembly.first().address
        val maxAddr = disassembly.last().address

        if (parsedAddr in minAddr..maxAddr) {
            return AddressResult(parsedAddr)
        }
        return null
    }
}
