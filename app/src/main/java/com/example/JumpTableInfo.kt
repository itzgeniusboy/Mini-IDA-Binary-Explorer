package com.example

data class JumpTableInfo(
    val branchInstructionAddr: Long,
    val tableBaseAddr: Long,
    val entryCount: Int,
    val caseTargets: List<Long>
)
