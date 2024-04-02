/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.learnlib.api.SUL
import de.learnlib.filter.statistic.Counter

class AdvancedStatisticSul<S : SUL<I, O>, I, O> private constructor(
    val nestedSul: S,
    private val totalSymbolCounter: Counter,
    private val totalResetCounter: Counter,
    private val learnSymbolCounter: Counter,
    private val learnResetCounter: Counter,
    private val equivSymbolCounter: Counter,
    private val equivResetCounter: Counter
) : SUL<I, O> {

    private var learningMode: Boolean = true

    constructor(sul: S) : this(
        sul,
        Counter("Total symbol count", "Symbols"),
        Counter("Total reset count", "Resets"),
        Counter("Symbol count during learning", "Symbols"),
        Counter("Reset count during learning", "Resets"),
        Counter("Symbol count during equivalence checks", "Symbols"),
        Counter("Reset count during equivalence checks", "Resets")
    )

    val totalSymbolCount
        get() = totalSymbolCounter.count
    val totalResetCount
        get() = totalResetCounter.count
    val learnSymbolCount
        get() = learnSymbolCounter.count
    val learnResetCount
        get() = learnResetCounter.count
    val equivSymbolCount
        get() = equivSymbolCounter.count
    val equivResetCount
        get() = equivResetCounter.count

    override fun pre() {
        totalResetCounter.increment()
        if (learningMode) {
            learnResetCounter.increment()
        } else {
            equivResetCounter.increment()
        }
        nestedSul.pre()
    }

    override fun post() {
        nestedSul.post()
    }

    override fun step(p0: I): O {
        totalSymbolCounter.increment()
        if (learningMode) {
            learnSymbolCounter.increment()
        } else {
            equivSymbolCounter.increment()
        }
        return nestedSul.step(p0)
    }

    override fun canFork(): Boolean {
        return nestedSul.canFork()
    }

    override fun fork(): SUL<I, O> {
        return AdvancedStatisticSul(
            nestedSul.fork(),
            totalSymbolCounter,
            totalResetCounter,
            learnSymbolCounter,
            learnResetCounter,
            equivSymbolCounter,
            equivResetCounter
        )
    }

    fun switchToEquivalenceCounters() {
        learningMode = false
    }

    fun switchToLearningCounters() {
        learningMode = true
    }
}
