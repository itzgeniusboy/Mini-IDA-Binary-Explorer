package com.example

enum class LoadStage {
    READING_HEADER,
    PARSING_SECTIONS,
    EXTRACTING_SYMBOLS,
    EXTRACTING_STRINGS,
    INDEXING_DB,
    MATCHING_SIGNATURES,
    RESOLVING_DATA_XREFS,
    DETECTING_JUMP_TABLES,
    DONE,
    ERROR
}

data class LoadProgress(
    val stage: LoadStage,
    val itemsProcessed: Int,
    val detail: String
)
