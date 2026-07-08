package com.example

enum class LoadStage {
    READING_HEADER,
    PARSING_SECTIONS,
    EXTRACTING_SYMBOLS,
    EXTRACTING_STRINGS,
    INDEXING_DB,
    MATCHING_SIGNATURES,
    RESOLVING_DATA_XREFS,
    DONE,
    ERROR
}

data class LoadProgress(
    val stage: LoadStage,
    val itemsProcessed: Int,
    val detail: String
)
