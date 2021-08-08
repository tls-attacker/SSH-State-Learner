/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.learner

import de.learnlib.api.SUL
import de.learnlib.api.oracle.EquivalenceOracle
import de.learnlib.api.query.DefaultQuery
import de.learnlib.filter.statistic.Counter
import de.learnlib.filter.statistic.sul.ResetCounterSUL
import de.learnlib.filter.statistic.sul.SymbolCounterSUL
import de.learnlib.oracle.equivalence.EQOracleChain
import de.learnlib.oracle.membership.SULOracle
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleType
import de.rub.nds.sshstatelearner.algorithms.LearningAlgorithmType
import de.rub.nds.sshstatelearner.learner.cache.ResponseTreeCache
import de.rub.nds.sshstatelearner.sul.SshSul
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.words.Alphabet
import net.automatalib.words.Word
import org.apache.logging.log4j.LogManager

class SshSulLearner(val alphabet: Alphabet<SshSymbol>, sul: SshSul, val algorithm: LearningAlgorithmType = LearningAlgorithmType.TTT, val equivalenceOracleType: EquivalenceOracleType = EquivalenceOracleType.RANDOM_WORDS) {

    var sul: SUL<SshSymbol, ResponseFingerprint>
        private set
    private val symbolCounter: Counter
    private val resetCounter: Counter

    private lateinit var membershipOracle: ResponseTreeCache
    private lateinit var equivalenceOracle: EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>>
    private lateinit var learningAlgorithm: de.learnlib.api.algorithm.LearningAlgorithm.MealyLearner<SshSymbol, ResponseFingerprint>

    init {
        this.sul = SymbolCounterSUL("Symbol Counter", sul)
        this.symbolCounter = (this.sul as SymbolCounterSUL<SshSymbol, ResponseFingerprint>).statisticalData
        this.sul = ResetCounterSUL("Reset Counter", this.sul)
        this.resetCounter = (this.sul as ResetCounterSUL<SshSymbol, ResponseFingerprint>).statisticalData
    }

    companion object {
        private val LOGGER = LogManager.getLogger()
    }

    private fun constructMembershipOracle(): ResponseTreeCache {
        return ResponseTreeCache(SULOracle(this.sul))
    }

    private fun constructEquivalenceOracle(): EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {
        return if (equivalenceOracleType == EquivalenceOracleType.RANDOM_WALK)
            EQOracleChain(
                membershipOracle.createCacheConsistencyTest(),
                EquivalenceOracleType.create(equivalenceOracleType, sul)
            )
        else
            EQOracleChain(
                membershipOracle.createCacheConsistencyTest(),
                EquivalenceOracleType.create(equivalenceOracleType, membershipOracle)
            )
    }

    private fun constructOracles() {
        membershipOracle = constructMembershipOracle()
        equivalenceOracle = constructEquivalenceOracle()
    }

    fun learn(): MealyMachine<*, SshSymbol, *, ResponseFingerprint> {
        constructOracles()
        learningAlgorithm = LearningAlgorithmType.create(algorithm, alphabet, membershipOracle)

        var hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>
        var counterExample: DefaultQuery<*, *>?
        var learningRound = 0

        val startTime = System.currentTimeMillis()
        learningAlgorithm.startLearning()
        do {
            hypothesis = learningAlgorithm.hypothesisModel
            LOGGER.info("Finished learning round ${learningRound++}, searching for counter examples (executed SUL steps: ${symbolCounter.count})")
            counterExample = equivalenceOracle.findCounterExample(hypothesis, alphabet)
            if (counterExample != null) {
                LOGGER.info("The equivalence oracle found a counter example: $counterExample")
                LOGGER.info("Passing counter example to learning algorithm for hypothesis refinement")
                learningAlgorithm.refineHypothesis(counterExample)
            }
        } while (counterExample != null)

        val endTime = System.currentTimeMillis()
        LOGGER.info("Finished learning the target SUL, took ${endTime - startTime} ms")
        LOGGER.info("Total steps: ${symbolCounter.count} | Total resets: ${resetCounter.count}")
        return hypothesis
    }
}
