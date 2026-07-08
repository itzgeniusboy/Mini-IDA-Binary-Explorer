package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

  @Test
  fun `read string from context`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val appName = context.getString(R.string.app_name)
    assertEquals("Mini IDA", appName)
  }

  @Test
  fun `test bookmark repository add and remove`() {
    val context = ApplicationProvider.getApplicationContext<Context>()
    val fileId = "test_lib.so"

    // 1. Initial State
    BookmarkRepository.loadBookmarks(context, fileId)
    assertFalse(BookmarkRepository.isBookmarked(0x1000L))

    // 2. Add Bookmark
    BookmarkRepository.addBookmark(context, fileId, 0x1000L, "test_func")
    assertTrue(BookmarkRepository.isBookmarked(0x1000L))

    val bookmarks = BookmarkRepository.getAllBookmarks()
    assertEquals(1, bookmarks.size)
    assertEquals("test_func", bookmarks[0].label)
    assertEquals(0x1000L, bookmarks[0].address)

    // 3. Remove Bookmark
    BookmarkRepository.removeBookmark(context, fileId, 0x1000L)
    assertFalse(BookmarkRepository.isBookmarked(0x1000L))
    assertEquals(0, BookmarkRepository.getAllBookmarks().size)
  }
}
