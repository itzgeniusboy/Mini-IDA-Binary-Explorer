package com.example

import android.content.Context

object BookmarkRepository {
    private val bookmarks = mutableMapOf<Long, BookmarkEntry>()
    private var currentFileId: String? = null

    /**
     * Initializes bookmarks for a given file ID from SQLite database.
     */
    fun loadBookmarks(context: Context, fileId: String) {
        currentFileId = fileId
        val dbHelper = OffsetsDatabaseHelper(context)
        bookmarks.clear()
        val dbList = dbHelper.getAllBookmarks(fileId)
        for (b in dbList) {
            bookmarks[b.address] = b
        }
    }

    /**
     * Clears all in-memory bookmarks.
     */
    fun clear() {
        bookmarks.clear()
        currentFileId = null
    }

    /**
     * Checks if an address is bookmarked in-memory.
     */
    fun isBookmarked(address: Long): Boolean {
        return bookmarks.containsKey(address)
    }

    /**
     * Gets a bookmark entry from in-memory cache.
     */
    fun getBookmark(address: Long): BookmarkEntry? {
        return bookmarks[address]
    }

    /**
     * Adds a bookmark to the database and in-memory cache.
     */
    fun addBookmark(context: Context, fileId: String, address: Long, label: String?) {
        val dbHelper = OffsetsDatabaseHelper(context)
        val createdAt = System.currentTimeMillis()
        dbHelper.addBookmark(fileId, address, label, createdAt)
        bookmarks[address] = BookmarkEntry(address, label, createdAt)
    }

    /**
     * Removes a bookmark from the database and in-memory cache.
     */
    fun removeBookmark(context: Context, fileId: String, address: Long) {
        val dbHelper = OffsetsDatabaseHelper(context)
        dbHelper.removeBookmark(fileId, address)
        bookmarks.remove(address)
    }

    /**
     * Retrieves all bookmarks sorted by address.
     */
    fun getAllBookmarks(): List<BookmarkEntry> {
        return bookmarks.values.sortedBy { it.address }
    }
}
