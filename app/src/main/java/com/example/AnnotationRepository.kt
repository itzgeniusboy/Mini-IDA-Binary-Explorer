package com.example

import android.content.Context

object AnnotationRepository {
    // In-memory map from address to AnnotationEntry
    private val annotations = mutableMapOf<Long, AnnotationEntry>()
    private var currentFileId: String? = null

    /**
     * Initializes annotations for a given file ID.
     */
    fun loadAnnotations(context: Context, fileId: String) {
        currentFileId = fileId
        val dbHelper = OffsetsDatabaseHelper(context)
        annotations.clear()
        annotations.putAll(dbHelper.getAllAnnotations(fileId))
    }

    /**
     * Clears all in-memory annotations.
     */
    fun clear() {
        annotations.clear()
        currentFileId = null
    }

    /**
     * Gets all loaded annotations in-memory.
     */
    fun getAllAnnotations(): Map<Long, AnnotationEntry> {
        return annotations
    }

    /**
     * Gets an annotation from the in-memory cache.
     */
    fun getAnnotation(address: Long): AnnotationEntry? {
        return annotations[address]
    }

    /**
     * Updates/saves an annotation both in-memory and in the database.
     */
    fun upsertAnnotation(context: Context, fileId: String, address: Long, customName: String?, comment: String?) {
        val dbHelper = OffsetsDatabaseHelper(context)
        dbHelper.upsertAnnotation(fileId, address, customName, comment)
        
        // Refresh cache
        val entry = AnnotationEntry(address, customName, comment, System.currentTimeMillis())
        annotations[address] = entry
    }

    /**
     * Deletes an annotation from the database and cache.
     */
    fun deleteAnnotation(context: Context, fileId: String, address: Long) {
        val dbHelper = OffsetsDatabaseHelper(context)
        dbHelper.deleteAnnotation(fileId, address)
        annotations.remove(address)
    }

    /**
     * Centralized display-name resolution.
     * Checks: annotation.customName if present, else demangled name, else raw mangled name, else "sub_<hex_address>" fallback.
     */
    fun resolveName(address: Long, fallbackName: String?): String {
        return resolveName("", address, fallbackName)
    }

    fun resolveName(fileId: String, address: Long, fallbackName: String?): String {
        val entry = annotations[address]
        if (entry != null && !entry.customName.isNullOrBlank()) {
            return entry.customName
        }

        if (fallbackName != null && fallbackName.isNotBlank()) {
            val demangled = ElfParser.demangleName(fallbackName)
            if (demangled.isNotBlank()) {
                return demangled
            }
            return fallbackName
        }

        // Sub fallback
        return "sub_${address.toString(16).uppercase()}"
    }

    private val functionNames = mutableMapOf<Long, String>()

    fun setFunctions(functions: List<ElfParser.ElfFunction>) {
        functionNames.clear()
        for (f in functions) {
            val clean = f.address.removePrefix("0x").removePrefix("0X")
            val addr = clean.toLongOrNull(16)
            if (addr != null) {
                functionNames[addr] = f.name
            }
        }
    }

    fun getFunctionName(address: Long): String? = functionNames[address]

    fun resolveAddressName(address: Long): String {
        val fallback = functionNames[address]
        return resolveName(address, fallback)
    }
}
