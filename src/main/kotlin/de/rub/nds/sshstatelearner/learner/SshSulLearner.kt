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
import de.learnlib.api.algorithm.LearningAlgorithm
import de.learnlib.api.oracle.EquivalenceOracle
import de.learnlib.api.query.DefaultQuery
import de.learnlib.filter.statistic.Counter
import de.learnlib.filter.statistic.sul.ResetCounterSUL
import de.learnlib.filter.statistic.sul.SymbolCounterSUL
import de.learnlib.oracle.membership.SULOracle
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleType
import de.rub.nds.sshstatelearner.algorithms.LearningAlgorithmFactory
import de.rub.nds.sshstatelearner.algorithms.LearningAlgorithmType
import de.rub.nds.sshstatelearner.learner.cache.ResponseTreeCache
import de.rub.nds.sshstatelearner.sul.SshSul
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import de.rub.nds.sshstatelearner.util.LoggerCompanion
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.words.Alphabet
import net.automatalib.words.Word

/**
 * A wrapper for learning an SSH SUL oracle. It exposes a single method, learn(), which constructs all necessary
 * oracles and conducts the specified learning algorithm on these oracles.
 *
 * @param alphabet The alphabet to use with the learning algorithm.
 * @param sul The SUL to learn.
 * @param algorithm The learning algorithm to use in order to learn the SUL.
 * @param equivalenceOracleChainTypes A list of equivalence oracle types to use as the equivalence oracle within the
 *                                    learning process.
 */
class SshSulLearner(
    val alphabet: Alphabet<SshSymbol>,
    sul: SshSul,
    val algorithm: LearningAlgorithmType = LearningAlgorithmType.TTT,
    val equivalenceOracleChainTypes: List<EquivalenceOracleType>
) {

    /**
     * The SUL to learn.
     */
    var sul: SUL<SshSymbol, ResponseFingerprint>
        private set

    /**
     * A simple counter representing the total number of symbols executed on the SUL.
     */
    private val symbolCounter: Counter
    /**
     * A simple counter representing the total number of resets executed on the SUL.
     */
    private val resetCounter: Counter

    /**
     * The membership oracle that is used within the learning algorithm. A cached variant of a SULOracle is used.
     */
    private lateinit var membershipOracle: ResponseTreeCache
    /**
     * The equivalence oracle that is used during the learning process.
     */
    private lateinit var equivalenceOracle: EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>>
    /**
     * The instance of the learning algorithm.
     */
    private lateinit var learningAlgorithm: LearningAlgorithm.MealyLearner<SshSymbol, ResponseFingerprint>

    /**
     * The output manager used to output intermediate and final hypothesis models. If set to null, the hypothesis
     * is not outputted.
     */
    var outputManager: OutputManager<SshSymbol>? = null

    init {
        this.sul = SymbolCounterSUL("Symbol Counter", sul)
        this.symbolCounter = (this.sul as SymbolCounterSUL<SshSymbol, ResponseFingerprint>).statisticalData
        this.sul = ResetCounterSUL("Reset Counter", this.sul)
        this.resetCounter = (this.sul as ResetCounterSUL<SshSymbol, ResponseFingerprint>).statisticalData
    }

    companion object : LoggerCompanion()

    /**
     * Constructs the membership and equivalence oracle to use within the learning process.
     */
    private fun constructOracles() {
        membershipOracle = ResponseTreeCache(SULOracle(sul))
        equivalenceOracle = EquivalenceOracleFactory.createChain(
            equivalenceOracleChainTypes,
            membershipOracle.asOracle(),
            sul,
            membershipOracle
        )
    }

    /**
     * Conducts the learning algorithm on the previously provided SUL.
     *
     * @return The final hypothesis of the learning algorithm.
     */
    fun learn(): MealyMachine<*, SshSymbol, *, ResponseFingerprint> {
        constructOracles()
        learningAlgorithm = LearningAlgorithmFactory.create(algorithm, alphabet, membershipOracle)
        outputManager?.prepare()

        var hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>
        var counterExample: DefaultQuery<*, *>?
        var learningRound = 0

        val startTime = System.currentTimeMillis()
        learningAlgorithm.startLearning()
        do {
            hypothesis = learningAlgorithm.hypothesisModel
            outputManager?.storeIntermediateHypothesis(alphabet, hypothesis, learningRound)
            LOGGER.info("Finished learning round ${learningRound++}, searching for counter examples (executed SUL steps: ${symbolCounter.count})")
            counterExample = equivalenceOracle.findCounterExample(hypothesis, alphabet)
            if (counterExample != null) {
                LOGGER.info("The equivalence oracle found a counter example: $counterExample")
                LOGGER.info("Passing counter example to learning algorithm for hypothesis refinement")
                learningAlgorithm.refineHypothesis(counterExample)
            }
        } while (counterExample != null)

        outputManager?.storeFinalHypothesis(alphabet, hypothesis, learningRound)
        val endTime = System.currentTimeMillis()
        LOGGER.info("Finished learning the target SUL, took ${endTime - startTime} ms")
        LOGGER.info("Total steps: ${symbolCounter.count} | Total resets: ${resetCounter.count}")
        return hypothesis
    }
}
