/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.extraction

import de.learnlib.oracle.EquivalenceOracle
import de.learnlib.query.DefaultQuery
import de.learnlib.oracle.membership.SULOracle
import de.rub.nds.sshstatelearner.SshStateMachine
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.algorithms.LearningAlgorithmFactory
import de.rub.nds.sshstatelearner.algorithms.ResponseTreeCache
import de.rub.nds.sshstatelearner.algorithms.ResponseTreeCacheWrapperForLearning
import de.rub.nds.sshstatelearner.algorithms.Statistics
import de.rub.nds.sshstatelearner.analysis.classifier.StateNameAndSuccessorTransition
import de.rub.nds.sshstatelearner.analysis.limiter.DFASMLLimiter
import de.rub.nds.sshstatelearner.analysis.limiter.EmptySMLLimiter
import de.rub.nds.sshstatelearner.analysis.limiter.SMLLimiter
import de.rub.nds.sshstatelearner.analysis.limiter.SMLLimiterTyp
import de.rub.nds.sshstatelearner.cli.MainWindow
import de.rub.nds.sshstatelearner.constants.EquivalenceOracleType
import de.rub.nds.sshstatelearner.constants.LearningAlgorithmType
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.db.QueryResultManager
import de.rub.nds.sshstatelearner.db.QueryTyp
import de.rub.nds.sshstatelearner.exceptions.CacheConflictException
import de.rub.nds.sshstatelearner.sul.AdvancedStatisticSul
import de.rub.nds.sshstatelearner.sul.SshSul
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.automaton.transducer.MealyMachine
import net.automatalib.alphabet.Alphabet
import net.automatalib.word.Word
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.File
import java.util.*

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
class ParallelOracleExtractor(
    private val alphabet: Alphabet<SshSymbol>,
    sul: SshSul,
    private val parallelSshSulSize: Int,
    private val algorithm: LearningAlgorithmType = LearningAlgorithmType.TTT,
    private val equivalenceOracleChainTypes: List<EquivalenceOracleType>,
    private val storeIntermediateHypotheses: Boolean,
    private val outputDirectory: String,
    private val isClient: Boolean,
    private val smlLimiterTyp: SMLLimiterTyp,
    private val pathToSmlLimiterFile: String,
    private val batchSize: Int,
    private val repeatedQueriesDuringLearningWithMajorityCount: Int,
    private val stateNameAndSuccessorTransitions: List<StateNameAndSuccessorTransition>,
    private val customProtocolStageNameForGraph: String,
    private val jsonString: String
) {

    /**
     * The SUL to learn.
     */
    private var sul: AdvancedStatisticSul<SshSul, SshSymbol, ResponseFingerprint>

    /**
     * The membership oracle that is used within the learning algorithm. A cached variant of a SULOracle is used.
     */
    private lateinit var membershipOracle: ResponseTreeCache

    /**
     * The equivalence oracle that is used during the learning process.
     */
    private lateinit var equivalenceOracle: EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>>

    /**
     * Number of learning algorithm restarts due to cache inconsistencies.
     */
    private var cacheInconsistencyRestarts: Int = 0

    /**
     * Unix time (in milliseconds) when
     */
    private var extractionStartTime: Long = 0

    /**
     * Number of learning rounds
     */
    private var rounds: Int = 0

    private val queryResult = QueryResultManager().apply { init() }

    /**
     * Timer used to schedule updates on the GUI at a fixed rate
     */
    private var guiUpdateTimer: Timer = Timer("GUIUpdateTimer")

    init {
        this.sul = AdvancedStatisticSul(sul).apply { AdvancedStatisticSul.resetData() }

    }

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    private fun createAndInitSMLLimiter(): SMLLimiter = when (smlLimiterTyp) {
        SMLLimiterTyp.EMPTY_SML_LIMITER -> EmptySMLLimiter()
        SMLLimiterTyp.DFA_SML_LIMITER -> DFASMLLimiter(pathToSmlLimiterFile)
    }


    /**
     * Constructs the membership and equivalence oracle to use within the learning process.
     */
    private fun constructOracles() {
        // Forks the SUL and then stores it in the cache
        val suls = mutableListOf<SULOracle<SshSymbol, ResponseFingerprint>>()
        repeat(parallelSshSulSize) {
            suls.add(SULOracle(sul.fork()))
        }
        membershipOracle =
            ResponseTreeCache(
                suls,
                createAndInitSMLLimiter(),
                repeatedQueriesDuringLearningWithMajorityCount,
                queryResult
            )
        equivalenceOracle = EquivalenceOracleFactory.createChain(
            equivalenceOracleChainTypes,
            membershipOracle,
            sul,
            membershipOracle,
            isClient,
            batchSize,
        )
    }

    fun extractStateMachine(): Extractor.ExtractorResult {
        constructOracles()
        var extractorResult: Extractor.ExtractorResult? = null
        cacheInconsistencyRestarts = 0
        extractionStartTime = System.currentTimeMillis()

        do {
            try {
                extractorResult = provideResult()
            } catch (e: CacheConflictException) {
                LOGGER.warn(e.message)
                val majorityResult = membershipOracle.answerQueryWithMajorityVote(
                    e.inputPrefix,
                    e.inputSuffix,
                    repeatedQueriesDuringLearningWithMajorityCount * 2
                )
                membershipOracle.overwrite(e.inputPrefix, e.inputSuffix, majorityResult)
                cacheInconsistencyRestarts++
            } catch (e: RuntimeException) {
                queryResult.waitUntilAllIsProcessed()
                queryResult.safeToDatabase(
                    jsonString
                )
                throw e
            }
        } while (extractorResult == null)

        return extractorResult
    }

    private fun createGUIUpdateTimer() {
        val task = object : TimerTask() {
            override fun run() {
                MainWindow.statLearningRound.text = rounds.toString()
                MainWindow.statLearningExecTime.text = "${(System.currentTimeMillis() - extractionStartTime) / 1000} s"
                MainWindow.statLearningSteps.text =
                    "${sul.totalSymbolCount} (${sul.learnSymbolCount} / ${sul.equivSymbolCount})"
                MainWindow.statLearningResets.text =
                    "${sul.totalResetCount} (${sul.learnResetCount} / ${sul.equivResetCount})"
                MainWindow.statLearningCacheInconsistencies.text = cacheInconsistencyRestarts.toString()
            }
        }
        guiUpdateTimer.scheduleAtFixedRate(task, 0, 250)
    }

    private fun provideResult(): Extractor.ExtractorResult {
        clearOutput()
        createGUIUpdateTimer()

        val extractorResult = Extractor.ExtractorResult()
        // The learning algorithm receives a wrapper for the cache so that only majority verified queries are used for the SML.
        val learningAlgorithm =
            LearningAlgorithmFactory.create(algorithm, alphabet, ResponseTreeCacheWrapperForLearning(membershipOracle))

        var hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>
        var counterExample: DefaultQuery<SshSymbol, Word<ResponseFingerprint>>?

        sul.switchToLearningCounters()
        MainWindow.statLearningPhase.text = "LEARNING"
        queryResult.switchToQueryTypes(QueryTyp.USED_TO_LEARN)
        learningAlgorithm.startLearning()
        do {
            hypothesis = learningAlgorithm.hypothesisModel
            val stateMachine =
                SshStateMachine(
                    hypothesis,
                    alphabet,
                    sul.nestedSul.name,
                    sul.nestedSul.stage,
                    sul.nestedSul.kex,
                    sul.nestedSul.strictKex,
                    stateNameAndSuccessorTransitions,
                    customProtocolStageNameForGraph
                )
            extractorResult.addHypothesis(stateMachine)

            if (storeIntermediateHypotheses) {
                // TODO: Remove analysis of intermediate hypotheses later on
                stateMachine.analyzeMealyMachine()
                serializeHypothesis(stateMachine, "hyp$rounds.dot")
            }
            LOGGER.warn("Finished learning round ${rounds++}, searching for counter examples (executed SUL steps: ${sul.totalSymbolCount})")

            sul.switchToEquivalenceCounters()
            MainWindow.statLearningPhase.text = "EQUIVALENCE CHECK"

            counterExample = findCounterExampleWithMajorityVote(hypothesis)
            LOGGER.warn("Finished counter example round ${rounds}, searching for counter examples (executed SUL steps: ${sul.totalSymbolCount})")
            if (counterExample != null) {
                LOGGER.info("The equivalence oracle found a counter example: $counterExample")
                LOGGER.info("Passing counter example to learning algorithm for hypothesis refinement")
                sul.switchToLearningCounters()
                MainWindow.statLearningPhase.text = "LEARNING"
                queryResult.switchToQueryTypes(QueryTyp.USED_TO_REFINE_HYPOTHESIS)
                learningAlgorithm.refineHypothesis(counterExample)
            }
        } while (counterExample != null)

        LOGGER.warn("Finished learning the target SUL after $rounds rounds")
        LOGGER.info("Total steps: ${sul.totalSymbolCount} (Learning: ${sul.learnSymbolCount} | Equivalence: ${sul.equivSymbolCount})")
        LOGGER.info("Total resets: ${sul.totalResetCount} (Learning: ${sul.learnResetCount} | Equivalence: ${sul.equivResetCount})")
        guiUpdateTimer.cancel()

        val stateMachine =
            SshStateMachine(
                hypothesis,
                alphabet,
                sul.nestedSul.name,
                sul.nestedSul.stage,
                sul.nestedSul.kex,
                sul.nestedSul.strictKex,
                stateNameAndSuccessorTransitions,
                customProtocolStageNameForGraph
            )
        val statistics = Statistics(
            states = stateMachine.mealyMachine.size(),
            counterExampleCount = rounds - 1,
            totalSymbolCount = sul.totalSymbolCount,
            totalResetCount = sul.totalResetCount,
            learnSymbolCount = sul.learnSymbolCount,
            learnResetCount = sul.learnResetCount,
            equivSymbolCount = sul.equivSymbolCount,
            equivResetCount = sul.equivResetCount,
            cacheInconsistencyRestarts = cacheInconsistencyRestarts,
            duration = System.currentTimeMillis() - extractionStartTime
        )
        extractorResult.learnedModel = stateMachine
        extractorResult.statistics = statistics
        queryResult.waitUntilAllIsProcessed()
        queryResult.setStatistics(statistics)
        queryResult.safeToDatabase(jsonString)
        return extractorResult
    }

    private fun findCounterExampleWithMajorityVote(hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>): DefaultQuery<SshSymbol, Word<ResponseFingerprint>>? {
        queryResult.switchToQueryTypes(QueryTyp.USED_TO_FIND_A_COUNTER_EXAMPLE)
        val counterExample = equivalenceOracle.findCounterExample(hypothesis, alphabet)
        queryResult.switchToQueryTypes(QueryTyp.USED_TO_FIND_MAJORITY_COUNTER_EXAMPLE)
        if (counterExample != null) {
            val counterExampleSafe =
                membershipOracle.answerQueryWithMajorityVote(counterExample.prefix, counterExample.suffix)
            counterExample.answer(counterExampleSafe)
            if (membershipOracle.isQueryValidInCacheContext(
                    counterExample.prefix,
                    counterExample.suffix,
                    counterExampleSafe
                )
            ) {
                membershipOracle.overwrite(counterExample.prefix, counterExample.suffix, counterExampleSafe)
            } else {
                //Error in learning: Trigger error in update..
                membershipOracle.update(counterExample.prefix, counterExample.suffix, counterExampleSafe)
                throw IllegalStateException("Trigger error in update did not work")
            }

        }
        return counterExample
    }

    private fun serializeHypothesis(hypothesis: SshStateMachine<*, *>, name: String) {
        val folder = File(outputDirectory).also { it.mkdirs() }
        val graphFile = File(folder, name)
        hypothesis.exportToDotAndPDF(graphFile, VisualizationDetail.MEDIUM)
    }

    private fun clearOutput() {
        val folder = File(outputDirectory).also { it.mkdirs() }
        for (file in folder.listFiles() ?: emptyArray()) {
            if (!file.isDirectory) file.delete()
        }
    }
}
