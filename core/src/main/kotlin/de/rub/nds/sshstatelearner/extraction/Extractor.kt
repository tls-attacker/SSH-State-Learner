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
import de.learnlib.oracle.ParallelOracle
import de.learnlib.oracle.ThreadPool
import de.learnlib.query.DefaultQuery
import de.learnlib.oracle.parallelism.ParallelOracleBuilders
import de.rub.nds.sshstatelearner.SshStateMachine
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.algorithms.LearningAlgorithmFactory
import de.rub.nds.sshstatelearner.algorithms.ParallelResponseTreeCache
import de.rub.nds.sshstatelearner.cli.MainWindow
import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.constants.EquivalenceOracleType
import de.rub.nds.sshstatelearner.constants.LearningAlgorithmType
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.exceptions.CacheConflictException
import de.rub.nds.sshstatelearner.sul.AdvancedStatisticSul
import de.rub.nds.sshstatelearner.sul.MajorityVoteOracle
import de.rub.nds.sshstatelearner.sul.SshSul
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.automaton.transducer.MealyMachine
import net.automatalib.alphabet.Alphabet
import net.automatalib.word.Word
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.File
import java.io.FileWriter
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
 * @param storeIntermediateHypotheses Whether to store intermediate hypotheses during the learning process.
 * @param outputDirectory The directory to store the intermediate hypotheses in.
 * @param majorityVotes The number of majority votes to use for every query to the SUL.
 * @param cacheConflictMajorityVotes The number of majority votes to use for queries that caused cache conflicts.
 */
class Extractor(
    private val alphabet: Alphabet<SshSymbol>,
    private val sshSulList: List<SshSul>,
    private val algorithm: LearningAlgorithmType = LearningAlgorithmType.TTT,
    private val equivalenceOracleChainTypes: List<EquivalenceOracleType>,
    private val storeIntermediateHypotheses: Boolean,
    private val outputDirectory: String,
    private val majorityVotes: Int = 1,
    private val cacheConflictMajorityVotes: Int = 7
) {

    /**
     * Data structure to store statistics about the learning process.
     */
    private val learningStats: AdvancedStatisticSul.Data = AdvancedStatisticSul.Data()

    /**
     * The list of SULs that are used to construct the oracles used in the learning process.
     */
    private val sulList: List<AdvancedStatisticSul<SshSul, SshSymbol, ResponseFingerprint>> = sshSulList.map { AdvancedStatisticSul(it, learningStats) }

    /**
     * The parallel oracle that is used within the learning algorithm.
     */
    private lateinit var oracle: ParallelOracle<SshSymbol, Word<ResponseFingerprint>>

    /**
     * The membership oracle that is used within the learning algorithm. A cached variant of a SULOracle is used.
     */
    private lateinit var membershipOracle: ParallelResponseTreeCache

    /**
     * The equivalence oracle that is used during the learning process.
     */
    private lateinit var equivalenceOracle: EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>>

    /**
     * Number of learning algorithm restarts due to cache inconsistencies.
     */
    private var cacheInconsistencyRestarts: Int = 0

    /**
     * Unix time (in milliseconds) when the extraction process started.
     */
    private var extractionStartTime: Long = 0

    /**
     * Number of learning rounds
     */
    private var rounds: Int = 0

    /**
     * The current size of the hypothesis state machine.
     */
    private var currentHypothesisSize: Int = 0

    /**
     * Timer used to schedule updates on the GUI at a fixed rate
     */
    private var guiUpdateTimer: Timer = Timer("GUIUpdateTimer")

    /**
     * Timer used to schedule saving of statistics at a fixed rate
     */
    private var statisticsSaveTimer: Timer = Timer("StatisticsSaveTimer")

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    /**
     * Constructs the membership and equivalence oracle to use within the learning process.
     */
    private fun constructOracles() {
        // Create a parallel membership oracle with the specified number of parallel SULs
        oracle = ParallelOracleBuilders
            .newStaticParallelOracle(sulList.map { MajorityVoteOracle(it, majorityVotes) }.toMutableList())
            .withMinBatchSize(5)
            .withPoolPolicy(ThreadPool.PoolPolicy.FIXED)
            .create()
        membershipOracle = ParallelResponseTreeCache(oracle, cacheConflictMajorityVotes)
        equivalenceOracle = EquivalenceOracleFactory.createChain(
            equivalenceOracleChainTypes,
            membershipOracle.asOracle(),
            sulList[0],
            sshSulList[0].sulType,
            membershipOracle,
            25 * sulList.size
        )
    }

    /**
     * Extracts a state machine from the provided SUL.
     *
     * @return The extracted state machine.
     */
    fun extractStateMachine(): ExtractorResult {
        clearOutput()
        constructOracles()
        var extractorResult: ExtractorResult? = null
        cacheInconsistencyRestarts = 0
        extractionStartTime = System.currentTimeMillis()

        do {
            try {
                extractorResult = provideResult()
            } catch (e: CacheConflictException) {
                // Handle unrecoverable cache conflict exception by logging the error and restarting the learning process
                // We maintain the current cache state to speed up the initial learning process
                LOGGER.error("${e.message}\nInput prefix: ${e.inputPrefix}\nInput suffix: ${e.inputSuffix}\nExpected output: ${e.expectedOutput}\nActual output: ${e.actualOutput}")
                currentHypothesisSize = 0
                saveStatistics(true)
                val majorityResult = MajorityVoteOracle(sulList[0], cacheConflictMajorityVotes).answerQuery(e.inputPrefix, e.inputSuffix)
                membershipOracle.update(e.inputPrefix, e.inputSuffix, majorityResult, true)
                cacheInconsistencyRestarts++
            }
        } while (extractorResult == null)
        oracle.shutdownNow()
        return extractorResult
    }

    /**
     * Saves the statistics of the learning process to a file in the output directory.
     */
    private fun saveStatistics(isCacheConflict: Boolean = false) : Statistics {
        val folder = File(ArgsGeneral.output).also { it.mkdirs() }
        val statistics = Statistics(
            states = currentHypothesisSize,
            counterExampleCount = rounds - 1,
            learningStats = learningStats.asImmutable(),
            cacheInconsistencyRestarts = cacheInconsistencyRestarts,
            cacheHitRate = membershipOracle.cacheHitRate,
            duration = System.currentTimeMillis() - extractionStartTime
        )
        val fileName = if (isCacheConflict) {
            "statistics_round${rounds}_conflict${cacheInconsistencyRestarts}.json"
        } else {
            "statistics.json"
        }
        val statsFile = File(folder, fileName).also { it.createNewFile() }
        with(FileWriter(statsFile)) {
            statistics.toString()
            statistics.export(this)
            this.close()
        }
        return statistics
    }

    /**
     * Creates a timer task that updates the GUI with the current learning statistics at a fixed rate.
     */
    private fun createGuiUpdateTimerTask() {
        val task = object : TimerTask() {
            override fun run() {
                MainWindow.statLearningRound.text = rounds.toString()
                MainWindow.statLearningExecTime.text = "${(System.currentTimeMillis() - extractionStartTime) / 1000} s"
                MainWindow.statLearningSteps.text =
                    "${learningStats.totalSymbolCount} (${learningStats.learnSymbolCount} / ${learningStats.equivSymbolCount})"
                MainWindow.statLearningResets.text =
                    "${learningStats.totalResetCount} (${learningStats.learnResetCount} / ${learningStats.equivResetCount})"
                MainWindow.statLearningCacheInconsistencies.text = cacheInconsistencyRestarts.toString()
                MainWindow.statLearningCacheHitRate.text = membershipOracle.cacheHitRate.toString()
            }
        }
        guiUpdateTimer.scheduleAtFixedRate(task, 0, 250)
    }

    /**
     * Creates a timer task that saves the learning statistics to a file at a fixed rate.
     */
    private fun createSaveStatisticsTimerTask() {
        val task = object : TimerTask() {
            override fun run() {
                saveStatistics()
            }
        }
        statisticsSaveTimer.scheduleAtFixedRate(task, 0, 10000)
    }

    /**
     * Conducts the learning process and returns the learned state machine.
     *
     * @return The learned state machine.
     */
    private fun provideResult(): ExtractorResult {
        createGuiUpdateTimerTask()
        createSaveStatisticsTimerTask()

        val extractorResult = ExtractorResult()
        val learningAlgorithm = LearningAlgorithmFactory.create(algorithm, alphabet, membershipOracle)

        var hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>
        var counterExample: DefaultQuery<SshSymbol, Word<ResponseFingerprint>>?

        sulList.forEach { it.switchToLearningCounters() }
        MainWindow.statLearningPhase.text = "LEARNING"
        learningAlgorithm.startLearning()
        do {
            hypothesis = learningAlgorithm.hypothesisModel
            val stateMachine =
                SshStateMachine(hypothesis, alphabet, sshSulList[0].name, sshSulList[0].stage, sshSulList[0].kex, sshSulList[0].strictKex)
            extractorResult.addHypothesis(stateMachine)
            currentHypothesisSize = stateMachine.mealyMachine.size()

            if (storeIntermediateHypotheses) {
                // TODO: Remove analysis of intermediate hypotheses later on
                stateMachine.analyzeMealyMachine()
                serializeHypothesis(stateMachine, "hyp$rounds.dot")
            }
            LOGGER.info("Finished learning round ${rounds++}, searching for counter examples (executed SUL steps: ${learningStats.totalSymbolCount})")

            sulList.forEach { it.switchToEquivalenceCounters() }
            MainWindow.statLearningPhase.text = "EQUIVALENCE CHECK"

            counterExample = equivalenceOracle.findCounterExample(hypothesis, alphabet)
            if (counterExample != null) {
                LOGGER.info("The equivalence oracle found a counter example: $counterExample")
                LOGGER.info("Passing counter example to learning algorithm for hypothesis refinement")
                sulList.forEach{ it.switchToLearningCounters() }
                MainWindow.statLearningPhase.text = "LEARNING"
                learningAlgorithm.refineHypothesis(counterExample)
            }
        } while (counterExample != null)

        LOGGER.info("Finished learning the target SUL after $rounds rounds")
        LOGGER.info("Total steps: ${learningStats.totalSymbolCount} (Learning: ${learningStats.learnSymbolCount} | Equivalence: ${learningStats.equivSymbolCount})")
        LOGGER.info("Total resets: ${learningStats.totalResetCount} (Learning: ${learningStats.learnResetCount} | Equivalence: ${learningStats.equivResetCount})")

        guiUpdateTimer.cancel()
        statisticsSaveTimer.cancel()

        val stateMachine =
            SshStateMachine(hypothesis, alphabet, sshSulList[0].name, sshSulList[0].stage, sshSulList[0].kex, sshSulList[0].strictKex)

        extractorResult.learnedModel = stateMachine
        extractorResult.statistics = saveStatistics()
        return extractorResult
    }

    /**
     * Serializes the hypothesis to a dot file and a PDF file.
     *
     * @param hypothesis The hypothesis to serialize.
     * @param name The name of the file to serialize the hypothesis to.
     */
    private fun serializeHypothesis(hypothesis: SshStateMachine<*, *>, name: String) {
        val folder = File(outputDirectory).also { it.mkdirs() }
        val graphFile = File(folder, name)
        hypothesis.exportToDotAndPDF(graphFile, VisualizationDetail.MEDIUM)
    }

    /**
     * Clears the output directory.
     */
    private fun clearOutput() {
        val folder = File(outputDirectory).also { it.mkdirs() }
        for (file in folder.listFiles() ?: emptyArray()) {
            if (!file.isDirectory) file.delete()
        }
    }

    class ExtractorResult {
        lateinit var learnedModel: SshStateMachine<*, *>
        lateinit var statistics: Statistics
        private val hypothesesMutable: MutableList<SshStateMachine<*, *>> = mutableListOf()

        val hypotheses: List<SshStateMachine<*, *>>
            get() = hypothesesMutable.toList()

        fun addHypothesis(hypothesis: SshStateMachine<*, *>) {
            hypothesesMutable.add(hypothesis)
        }
    }
}
