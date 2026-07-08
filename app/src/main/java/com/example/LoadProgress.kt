package com.example

enum class LoadStage {
    READING_HEADER,
    PARSING_SECTIONS,
    EXTRACTING_SYMBOLS,
    EXTRACTING_STRINGS,
    INDEXING_DB,
    DONE,
    ERROR
}

data class LoadProgress(
    val stage: LoadStage,
    val itemsProcessed: Int,
    val detail: String
)
