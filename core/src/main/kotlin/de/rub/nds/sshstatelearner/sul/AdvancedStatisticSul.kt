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
import java.util.concurrent.atomic.AtomicBoolean

class AdvancedStatisticSul<S : SUL<I, O>, I, O> constructor(
    val nestedSul: S,
) : SUL<I, O> {

    companion object {
        private val totalSymbolCounter: Counter = Counter("Total symbol count", "Symbols")
        private val totalResetCounter: Counter = Counter("Total reset count", "Resets")
        private val learnSymbolCounter: Counter = Counter("Symbol count during learning", "Symbols")
        private val learnResetCounter: Counter = Counter("Reset count during learning", "Resets")
        private val equivSymbolCounter: Counter = Counter("Symbol count during equivalence checks", "Symbols")
        private val equivResetCounter: Counter = Counter("Reset count during equivalence checks", "Resets")
        private var learningMode: AtomicBoolean = AtomicBoolean(true)
    }

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
        if (learningMode.get()) {
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
        if (learningMode.get()) {
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
        )
    }

    fun switchToEquivalenceCounters() {
        learningMode.set(false)
    }

    fun switchToLearningCounters() {
        learningMode.set(true)
    }
}
