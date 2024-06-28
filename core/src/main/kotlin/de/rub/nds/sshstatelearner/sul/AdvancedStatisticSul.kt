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
        fun resetData() {
            data = Data()
        }

        private var data = Data()
    }

    val totalSymbolCount
        get() = data.totalSymbolCounter.count
    val totalResetCount
        get() = data.totalResetCounter.count
    val learnSymbolCount
        get() = data.learnSymbolCounter.count
    val learnResetCount
        get() = data.learnResetCounter.count
    val equivSymbolCount
        get() = data.equivSymbolCounter.count
    val equivResetCount
        get() = data.equivResetCounter.count

    override fun pre() {
        data.totalResetCounter.increment()
        if (data.learningMode.get()) {
            data.learnResetCounter.increment()
        } else {
            data.equivResetCounter.increment()
        }
        nestedSul.pre()
    }

    override fun post() {
        nestedSul.post()
    }

    override fun step(p0: I): O {
        data.totalSymbolCounter.increment()
        if (data.learningMode.get()) {
            data.learnSymbolCounter.increment()
        } else {
            data.equivSymbolCounter.increment()
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
        data.learningMode.set(false)
    }

    fun switchToLearningCounters() {
        data.learningMode.set(true)
    }

    private class Data {
        val totalSymbolCounter: Counter = Counter("Total symbol count", "Symbols")
        val totalResetCounter: Counter = Counter("Total reset count", "Resets")
        val learnSymbolCounter: Counter = Counter("Symbol count during learning", "Symbols")
        val learnResetCounter: Counter = Counter("Reset count during learning", "Resets")
        val equivSymbolCounter: Counter = Counter("Symbol count during equivalence checks", "Symbols")
        val equivResetCounter: Counter = Counter("Reset count during equivalence checks", "Resets")
        var learningMode: AtomicBoolean = AtomicBoolean(true)
    }
}
