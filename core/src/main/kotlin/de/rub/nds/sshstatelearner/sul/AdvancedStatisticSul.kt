/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.learnlib.sul.SUL
import de.learnlib.filter.statistic.Counter
import kotlinx.serialization.Serializable
import java.util.concurrent.atomic.AtomicBoolean

class AdvancedStatisticSul<S : SUL<I, O>, I, O>(
    private val nestedSul: S,
    val data: Data
) : SUL<I, O> {

    private var currentIteration = 0

    override fun pre() {
        data.totalResetCounter.increment()
        data.iterationData[currentIteration].totalResetCounter.increment()
        if (data.learningMode.get()) {
            data.learnResetCounter.increment()
            data.iterationData[currentIteration].learnResetCounter.increment()
        } else {
            data.equivResetCounter.increment()
            data.iterationData[currentIteration].equivResetCounter.increment()
        }
        nestedSul.pre()
    }

    override fun post() {
        nestedSul.post()
    }

    override fun step(p0: I): O {
        data.totalSymbolCounter.increment()
        data.iterationData[currentIteration].totalSymbolCounter.increment()
        if (data.learningMode.get()) {
            data.learnSymbolCounter.increment()
            data.iterationData[currentIteration].learnSymbolCounter.increment()
        } else {
            data.equivSymbolCounter.increment()
            data.iterationData[currentIteration].equivSymbolCounter.increment()
        }
        return nestedSul.step(p0)
    }

    override fun canFork(): Boolean {
        return nestedSul.canFork()
    }

    override fun fork(): SUL<I, O> {
        return AdvancedStatisticSul(
            nestedSul.fork(),
            data
        )
    }

    @Synchronized
    fun switchToEquivalenceCounters() {
        data.learningMode.set(false)
        currentIteration++
        if (data.iterationData.getOrNull(currentIteration) == null) {
            data.iterationData.add(IterationData(currentIteration))
        }
    }

    fun switchToLearningCounters() {
        data.learningMode.set(true)
    }

    abstract class AbstractData {
        val totalSymbolCounter: Counter = Counter("Total symbol count", "Symbols")
        val totalResetCounter: Counter = Counter("Total reset count", "Resets")
        val learnSymbolCounter: Counter = Counter("Symbol count during learning", "Symbols")
        val learnResetCounter: Counter = Counter("Reset count during learning", "Resets")
        val equivSymbolCounter: Counter = Counter("Symbol count during equivalence checks", "Symbols")
        val equivResetCounter: Counter = Counter("Reset count during equivalence checks", "Resets")

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
    }

    class Data : AbstractData() {
        val iterationData: MutableList<IterationData> = mutableListOf(IterationData(0))
        var learningMode: AtomicBoolean = AtomicBoolean(true)

        fun asImmutable(): ImmutableData {
            return ImmutableData(
                totalSymbolCount = totalSymbolCount,
                totalResetCount = totalResetCount,
                learnSymbolCount = learnSymbolCount,
                learnResetCount = learnResetCount,
                equivSymbolCount = equivSymbolCount,
                equivResetCount = equivResetCount,
                iterationData = iterationData.map {
                    ImmutableIterationData(
                        iteration = it.iteration,
                        totalSymbolCount = it.totalSymbolCounter.count,
                        totalResetCount = it.totalResetCounter.count,
                        learnSymbolCount = it.learnSymbolCounter.count,
                        learnResetCount = it.learnResetCounter.count,
                        equivSymbolCount = it.equivSymbolCounter.count,
                        equivResetCount = it.equivResetCounter.count
                    )
                }
            )
        }
    }

    class IterationData(val iteration: Int): AbstractData()

    @Serializable
    data class ImmutableData(
        val totalSymbolCount: Long,
        val totalResetCount: Long,
        val learnSymbolCount: Long,
        val learnResetCount: Long,
        val equivSymbolCount: Long,
        val equivResetCount: Long,
        val iterationData: List<ImmutableIterationData>
    )

    @Serializable
    data class ImmutableIterationData(
        val iteration: Int,
        val totalSymbolCount: Long,
        val totalResetCount: Long,
        val learnSymbolCount: Long,
        val learnResetCount: Long,
        val equivSymbolCount: Long,
        val equivResetCount: Long
    )
}
