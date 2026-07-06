package com.example

import android.content.Context
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper

class OffsetsDatabaseHelper(context: Context) : SQLiteOpenHelper(context, DATABASE_NAME, null, DATABASE_VERSION) {

    companion object {
        const val DATABASE_NAME = "offsets.db"
        const val DATABASE_VERSION = 1

        const val TABLE_OFFSETS = "offsets"
        const val COLUMN_ID = "id"
        const val COLUMN_OFFSET_HEX = "offset_hex"
        const val COLUMN_SYMBOL_NAME = "symbol_name"
        const val COLUMN_ARCH_TYPE = "arch_type" // "32" or "64"
    }

    override fun onCreate(db: SQLiteDatabase) {
        val createTableQuery = """
            CREATE TABLE $TABLE_OFFSETS (
                $COLUMN_ID INTEGER PRIMARY KEY AUTOINCREMENT,
                $COLUMN_OFFSET_HEX TEXT,
                $COLUMN_SYMBOL_NAME TEXT,
                $COLUMN_ARCH_TYPE TEXT
            )
        """.trimIndent()
        db.execSQL(createTableQuery)

        db.execSQL("CREATE INDEX idx_offset_hex ON $TABLE_OFFSETS ($COLUMN_OFFSET_HEX)")
        db.execSQL("CREATE INDEX idx_symbol_name ON $TABLE_OFFSETS ($COLUMN_SYMBOL_NAME)")
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS $TABLE_OFFSETS")
        onCreate(db)
    }

    fun insertOffsetsBulk(functions: List<ElfParser.ElfFunction>, archType: String) {
        val db = writableDatabase
        db.beginTransaction()
        try {
            val query = "INSERT INTO $TABLE_OFFSETS ($COLUMN_OFFSET_HEX, $COLUMN_SYMBOL_NAME, $COLUMN_ARCH_TYPE) VALUES (?, ?, ?)"
            val statement = db.compileStatement(query)
            
            for (func in functions) {
                statement.clearBindings()
                statement.bindString(1, func.address)
                statement.bindString(2, func.name)
                statement.bindString(3, archType)
                statement.executeInsert()
            }
            db.setTransactionSuccessful()
        } finally {
            db.endTransaction()
        }
    }

    fun searchOffsetsPaginated(searchQuery: String?, limit: Int, offset: Int): List<ElfParser.ElfFunction> {
        val db = readableDatabase
        val list = mutableListOf<ElfParser.ElfFunction>()
        
        val cursor: Cursor = if (searchQuery.isNullOrBlank()) {
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
}
