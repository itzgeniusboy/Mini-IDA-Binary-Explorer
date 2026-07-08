package com.example

import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class OffsetsDatabaseHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        const val DATABASE_NAME = "offsets.db"
        const val DATABASE_VERSION = 5

        const val TABLE_OFFSETS = "offsets"
        const val COLUMN_ID = "id"
        const val COLUMN_OFFSET_HEX = "offset_hex"
        const val COLUMN_SYMBOL_NAME = "symbol_name"
        const val COLUMN_ARCH_TYPE = "arch_type" // "32" or "64"
        const val COLUMN_FILE_IDENTIFIER = "file_identifier" // path/name of file
    }

    override fun onCreate(db: SQLiteDatabase) {
        val createTableQuery = """
            CREATE TABLE $TABLE_OFFSETS (
                $COLUMN_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COLUMN_OFFSET_HEX TEXT,
                $COLUMN_SYMBOL_NAME TEXT,
                $COLUMN_ARCH_TYPE TEXT,
                $COLUMN_FILE_IDENTIFIER TEXT
            )
        """.trimIndent()
        db.execSQL(createTableQuery)

        db.execSQL("CREATE INDEX idx_offset_hex ON $TABLE_OFFSETS ($COLUMN_OFFSET_HEX)")
        db.execSQL("CREATE INDEX idx_symbol_name ON $TABLE_OFFSETS ($COLUMN_SYMBOL_NAME)")
        db.execSQL("CREATE INDEX idx_file_identifier ON $TABLE_OFFSETS ($COLUMN_FILE_IDENTIFIER)")

        // Add xrefs table
        val createXrefsTableQuery = """
            CREATE TABLE xrefs (
                file_id TEXT,
                from_addr INTEGER,
                to_addr INTEGER,
                xref_type TEXT
            )
        """.trimIndent()
        db.execSQL(createXrefsTableQuery)

        db.execSQL("CREATE INDEX idx_xrefs_file_id ON xrefs (file_id)")
        db.execSQL("CREATE INDEX idx_xrefs_from ON xrefs (from_addr)")
        db.execSQL("CREATE INDEX idx_xrefs_to ON xrefs (to_addr)")

        // Add annotations table
        val createAnnotationsTableQuery = """
            CREATE TABLE annotations (
                file_id TEXT,
                address INTEGER,
                custom_name TEXT,
                comment TEXT,
                updated_at INTEGER,
                PRIMARY KEY(file_id, address)
            )
        """.trimIndent()
        db.execSQL(createAnnotationsTableQuery)

        db.execSQL("CREATE INDEX idx_annotations_file_id ON annotations (file_id)")
        db.execSQL("CREATE INDEX idx_annotations_address ON annotations (address)")

        // Add bookmarks table
        val createBookmarksTableQuery = """
            CREATE TABLE bookmarks (
                file_id TEXT,
                address INTEGER,
                label TEXT,
                created_at INTEGER,
                PRIMARY KEY(file_id, address)
            )
        """.trimIndent()
        db.execSQL(createBookmarksTableQuery)

        db.execSQL("CREATE INDEX idx_bookmarks_file_id ON bookmarks (file_id)")
        db.execSQL("CREATE INDEX idx_bookmarks_address ON bookmarks (address)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_OFFSETS")
        db.execSQL("DROP TABLE IF EXISTS xrefs")
        db.execSQL("DROP TABLE IF EXISTS annotations")
        db.execSQL("DROP TABLE IF EXISTS bookmarks")
        onCreate(db)
    }

    fun insertOffsetsBulk(fileIdentifier: String, functions: List<ElfParser.ElfFunction>, archType: String, onProgress: ((Int) -> Unit)? = null) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            // First clear any previous entries for this exact file identifier
            db.delete(TABLE_OFFSETS, "$COLUMN_FILE_IDENTIFIER = ?", arrayOf(fileIdentifier))

            val query = "INSERT INTO $TABLE_OFFSETS ($COLUMN_OFFSET_HEX, $COLUMN_SYMBOL_NAME, $COLUMN_ARCH_TYPE, $COLUMN_FILE_IDENTIFIER) VALUES (?, ?, ?, ?)"
            val statement = db.compileStatement(query)
            
            for ((index, func) in functions.withIndex()) {
                if (index % 1000 == 0 && index > 0) {
                    onProgress?.invoke(index)
                }
                statement.clearBindings()
                statement.bindString(1, func.address)
                statement.bindString(2, func.name)
                statement.bindString(3, archType)
                statement.bindString(4, fileIdentifier)
                statement.executeInsert()
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun searchOffsetsPaginated(searchQuery: String?, fileIdentifier: String?, limit: Int, offset: Int): List<ElfParser.ElfFunction> {
        val db = readableDatabase
        val list = mutableListOf<ElfParser.ElfFunction>()
        
        val cursor: Cursor = if (fileIdentifier.isNullOrBlank()) {
            if (searchQuery.isNullOrBlank()) {
                val selectQuery = """
                    SELECT $COLUMN_OFFSET_HEX, $COLUMN_SYMBOL_NAME, $COLUMN_ARCH_TYPE, $COLUMN_ID 
                    FROM $TABLE_OFFSETS 
                    LIMIT ? OFFSET ?
                """.trimIndent()
                db.rawQuery(selectQuery, arrayOf(limit.toString(), offset.toString()))
            } else {
                val selectQuery = """
                    SELECT $COLUMN_OFFSET_HEX, $COLUMN_SYMBOL_NAME, $COLUMN_ARCH_TYPE, $COLUMN_ID 
                    FROM $TABLE_OFFSETS 
                    WHERE $COLUMN_SYMBOL_NAME LIKE ? 
                    LIMIT ? OFFSET ?
                """.trimIndent()
                db.rawQuery(selectQuery, arrayOf("%$searchQuery%", limit.toString(), offset.toString()))
            }
        } else {
            if (searchQuery.isNullOrBlank()) {
                val selectQuery = """
                    SELECT $COLUMN_OFFSET_HEX, $COLUMN_SYMBOL_NAME, $COLUMN_ARCH_TYPE, $COLUMN_ID 
                    FROM $TABLE_OFFSETS 
                    WHERE $COLUMN_FILE_IDENTIFIER = ?
                    LIMIT ? OFFSET ?
                """.trimIndent()
                db.rawQuery(selectQuery, arrayOf(fileIdentifier, limit.toString(), offset.toString()))
            } else {
                val selectQuery = """
                    SELECT $COLUMN_OFFSET_HEX, $COLUMN_SYMBOL_NAME, $COLUMN_ARCH_TYPE, $COLUMN_ID 
                    FROM $TABLE_OFFSETS 
                    WHERE $COLUMN_FILE_IDENTIFIER = ? AND $COLUMN_SYMBOL_NAME LIKE ? 
                    LIMIT ? OFFSET ?
                """.trimIndent()
                db.rawQuery(selectQuery, arrayOf(fileIdentifier, "%$searchQuery%", limit.toString(), offset.toString()))
            }
        }

        cursor.use {
            val hexIdx = cursor.getColumnIndex(COLUMN_OFFSET_HEX)
            val nameIdx = cursor.getColumnIndex(COLUMN_SYMBOL_NAME)
            val idIdx = cursor.getColumnIndex(COLUMN_ID)
            
            while (cursor.moveToNext()) {
                val hex = if (hexIdx != -1) cursor.getString(hexIdx) else ""
                val name = if (nameIdx != -1) cursor.getString(nameIdx) else ""
                val id = if (idIdx != -1) cursor.getInt(idIdx) else 0
                
                list.add(
                    ElfParser.ElfFunction(
                        address = hex,
                        name = name,
                        size = "0 bytes",
                        bind = "GLOBAL",
                        type = "FUNC",
                        index = id
                    )
                )
            }
        }
        return list
    }

    fun insertXrefs(fileId: String, xrefList: List<XrefEntry>) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            db.delete("xrefs", "file_id = ?", arrayOf(fileId))

            val query = "INSERT INTO xrefs (file_id, from_addr, to_addr, xref_type) VALUES (?, ?, ?, ?)"
            val statement = db.compileStatement(query)

            for (xref in xrefList) {
                statement.clearBindings()
                statement.bindString(1, fileId)
                statement.bindLong(2, xref.fromAddr)
                statement.bindLong(3, xref.toAddr)
                statement.bindString(4, xref.type)
                statement.executeInsert()
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun getXrefsTo(fileId: String, address: Long): List<XrefEntry> {
        val db = readableDatabase
        val list = mutableListOf<XrefEntry>()
        val query = "SELECT from_addr, to_addr, xref_type FROM xrefs WHERE file_id = ? AND to_addr = ?"
        val cursor = db.rawQuery(query, arrayOf(fileId, address.toString()))
        cursor.use {
            val fromIdx = cursor.getColumnIndex("from_addr")
            val toIdx = cursor.getColumnIndex("to_addr")
            val typeIdx = cursor.getColumnIndex("xref_type")
            while (cursor.moveToNext()) {
                val from = if (fromIdx != -1) cursor.getLong(fromIdx) else 0L
                val to = if (toIdx != -1) cursor.getLong(toIdx) else 0L
                val type = if (typeIdx != -1) cursor.getString(typeIdx) else ""
                list.add(XrefEntry(from, to, type))
            }
        }
        return list
    }

    fun getXrefsFrom(fileId: String, address: Long): List<XrefEntry> {
        val db = readableDatabase
        val list = mutableListOf<XrefEntry>()
        val query = "SELECT from_addr, to_addr, xref_type FROM xrefs WHERE file_id = ? AND from_addr = ?"
        val cursor = db.rawQuery(query, arrayOf(fileId, address.toString()))
        cursor.use {
            val fromIdx = cursor.getColumnIndex("from_addr")
            val toIdx = cursor.getColumnIndex("to_addr")
            val typeIdx = cursor.getColumnIndex("xref_type")
            while (cursor.moveToNext()) {
                val from = if (fromIdx != -1) cursor.getLong(fromIdx) else 0L
                val to = if (toIdx != -1) cursor.getLong(toIdx) else 0L
                val type = if (typeIdx != -1) cursor.getString(typeIdx) else ""
                list.add(XrefEntry(from, to, type))
            }
        }
        return list
    }

    fun upsertAnnotation(fileId: String, address: Long, customName: String?, comment: String?) {
        val db = writableDatabase
        val query = """
            INSERT OR REPLACE INTO annotations (file_id, address, custom_name, comment, updated_at)
            VALUES (?, ?, ?, ?, ?)
        """.trimIndent()
        val statement = db.compileStatement(query)
        statement.clearBindings()
        statement.bindString(1, fileId)
        statement.bindLong(2, address)
        if (customName != null) {
            statement.bindString(3, customName)
        } else {
            statement.bindNull(3)
        }
        if (comment != null) {
            statement.bindString(4, comment)
        } else {
            statement.bindNull(4)
        }
        statement.bindLong(5, System.currentTimeMillis())
        statement.executeInsert()
    }

    fun getAnnotation(fileId: String, address: Long): AnnotationEntry? {
        val db = readableDatabase
        val query = "SELECT custom_name, comment, updated_at FROM annotations WHERE file_id = ? AND address = ?"
        val cursor = db.rawQuery(query, arrayOf(fileId, address.toString()))
        cursor.use {
            if (cursor.moveToFirst()) {
                val nameIdx = cursor.getColumnIndex("custom_name")
                val commentIdx = cursor.getColumnIndex("comment")
                val updatedIdx = cursor.getColumnIndex("updated_at")

                val customName = if (nameIdx != -1 && !cursor.isNull(nameIdx)) cursor.getString(nameIdx) else null
                val comment = if (commentIdx != -1 && !cursor.isNull(commentIdx)) cursor.getString(commentIdx) else null
                val updatedAt = if (updatedIdx != -1) cursor.getLong(updatedIdx) else 0L
                return AnnotationEntry(address, customName, comment, updatedAt)
            }
        }
        return null
    }

    fun getAllAnnotations(fileId: String): Map<Long, AnnotationEntry> {
        val db = readableDatabase
        val map = mutableMapOf<Long, AnnotationEntry>()
        val query = "SELECT address, custom_name, comment, updated_at FROM annotations WHERE file_id = ?"
        val cursor = db.rawQuery(query, arrayOf(fileId))
        cursor.use {
            val addrIdx = cursor.getColumnIndex("address")
            val nameIdx = cursor.getColumnIndex("custom_name")
            val commentIdx = cursor.getColumnIndex("comment")
            val updatedIdx = cursor.getColumnIndex("updated_at")

            while (cursor.moveToNext()) {
                val address = if (addrIdx != -1) cursor.getLong(addrIdx) else 0L
                val customName = if (nameIdx != -1 && !cursor.isNull(nameIdx)) cursor.getString(nameIdx) else null
                val comment = if (commentIdx != -1 && !cursor.isNull(commentIdx)) cursor.getString(commentIdx) else null
                val updatedAt = if (updatedIdx != -1) cursor.getLong(updatedIdx) else 0L
                map[address] = AnnotationEntry(address, customName, comment, updatedAt)
            }
        }
        return map
    }

    fun deleteAnnotation(fileId: String, address: Long) {
        val db = writableDatabase
        db.delete("annotations", "file_id = ? AND address = ?", arrayOf(fileId, address.toString()))
    }

    // --- STREAMING CURSOR METHODS FOR EXPORT ---

    fun getSymbolsCursor(fileId: String): Cursor {
        val db = readableDatabase
        val query = "SELECT $COLUMN_OFFSET_HEX, $COLUMN_SYMBOL_NAME FROM $TABLE_OFFSETS WHERE $COLUMN_FILE_IDENTIFIER = ? ORDER BY $COLUMN_ID ASC"
        return db.rawQuery(query, arrayOf(fileId))
    }

    fun getXrefsCursor(fileId: String): Cursor {
        val db = readableDatabase
        val query = "SELECT from_addr, to_addr, xref_type FROM xrefs WHERE file_id = ?"
        return db.rawQuery(query, arrayOf(fileId))
    }

    fun getAnnotationsCursor(fileId: String): Cursor {
        val db = readableDatabase
        val query = "SELECT address, custom_name, comment, updated_at FROM annotations WHERE file_id = ?"
        return db.rawQuery(query, arrayOf(fileId))
    }

    fun addBookmark(fileId: String, address: Long, label: String?, createdAt: Long) {
        val db = writableDatabase
        val query = """
            INSERT OR REPLACE INTO bookmarks (file_id, address, label, created_at)
            VALUES (?, ?, ?, ?)
        """.trimIndent()
        val statement = db.compileStatement(query)
        statement.clearBindings()
        statement.bindString(1, fileId)
        statement.bindLong(2, address)
        if (label != null) {
            statement.bindString(3, label)
        } else {
            statement.bindNull(3)
        }
        statement.bindLong(4, createdAt)
        statement.executeInsert()
    }

    fun removeBookmark(fileId: String, address: Long) {
        val db = writableDatabase
        db.delete("bookmarks", "file_id = ? AND address = ?", arrayOf(fileId, address.toString()))
    }

    fun isBookmarked(fileId: String, address: Long): Boolean {
        val db = readableDatabase
        val query = "SELECT 1 FROM bookmarks WHERE file_id = ? AND address = ?"
        val cursor = db.rawQuery(query, arrayOf(fileId, address.toString()))
        cursor.use {
            return cursor.count > 0
        }
    }

    fun getAllBookmarks(fileId: String): List<BookmarkEntry> {
        val db = readableDatabase
        val list = mutableListOf<BookmarkEntry>()
        val query = "SELECT address, label, created_at FROM bookmarks WHERE file_id = ? ORDER BY address ASC"
        val cursor = db.rawQuery(query, arrayOf(fileId))
        cursor.use {
            val addrIdx = cursor.getColumnIndex("address")
            val labelIdx = cursor.getColumnIndex("label")
            val createdIdx = cursor.getColumnIndex("created_at")
            while (cursor.moveToNext()) {
                val address = if (addrIdx != -1) cursor.getLong(addrIdx) else 0L
                val label = if (labelIdx != -1 && !cursor.isNull(labelIdx)) cursor.getString(labelIdx) else null
                val createdAt = if (createdIdx != -1) cursor.getLong(createdIdx) else 0L
                list.add(BookmarkEntry(address, label, createdAt))
            }
        }
        return list
    }
}
