package com.example

class NavigationController(private val onNavigation: (Long) -> Unit) {
    private val history = mutableListOf<Long>()
    private var currentIndex = -1

    fun navigateTo(address: Long, notify: Boolean = true) {
        if (currentIndex >= 0 && history[currentIndex] == address) {
            return
        }

        // Clear forward stack if we were in the middle of history
        if (currentIndex >= 0 && currentIndex < history.size - 1) {
            val itemsToRemove = history.size - 1 - currentIndex
            for (i in 0 until itemsToRemove) {
                history.removeAt(history.size - 1)
            }
        }

        history.add(address)
        currentIndex = history.size - 1

        if (notify) {
            onNavigation(address)
        }
    }

    fun goBack(): Boolean {
        if (canGoBack()) {
            currentIndex--
            onNavigation(history[currentIndex])
            return true
        }
        return false
    }

    fun goForward(): Boolean {
        if (canGoForward()) {
            currentIndex++
            onNavigation(history[currentIndex])
            return true
        }
        return false
    }

    fun canGoBack(): Boolean {
        return currentIndex > 0
    }

    fun canGoForward(): Boolean {
        return currentIndex < history.size - 1
    }

    fun clear() {
        history.clear()
        currentIndex = -1
    }
}
