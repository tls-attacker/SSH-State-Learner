/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms

import java.io.PrintWriter
import java.io.StringWriter
import java.io.Writer

data class Statistics(
    val states: Int,
    val counterExampleCount: Int,
    val totalSymbolCount: Long,
    val totalResetCount: Long,
    val learnSymbolCount: Long,
    val learnResetCount: Long,
    val equivSymbolCount: Long,
    val equivResetCount: Long,
    val cacheInconsistencyRestarts: Int,
    val duration: Long
) {
    override fun toString(): String =
        StringWriter().apply {
            export(this)
        }.toString()

    fun export(writer: Writer) =
        PrintWriter(writer).run {
            println("=== STATISTICS ===")
            println("Number of states: $states")
            println("Number of counter examples / hypotheses: $counterExampleCount")
            println("Total number of steps: $totalSymbolCount")
            println("Total number of resets: $totalResetCount")
            println("Number of steps during learning: $learnSymbolCount")
            println("Number of resets during learning: $learnResetCount")
            println("Number of steps during equivalence checks: $equivSymbolCount")
            println("Number of resets during equivalence checks: $equivResetCount")
            println("Number of restarts due to cache inconsistencies: $cacheInconsistencyRestarts")
            println("Time it took to learn state machine: $duration milliseconds")
        }
}
