/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.cli.args

import com.beust.jcommander.Parameter
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleFactory
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleType
import de.rub.nds.sshstatelearner.algorithms.LearningAlgorithmType
import de.rub.nds.sshstatelearner.learner.OutputFormat

/**
 * This object contains all arguments for the JCommander CLI parser which change the behaviour of the SUL learner. This
 * includes algorithms, equivalence oracle defaults and output formats.
 */
object ArgsLearner {
    @Parameter(names = ["--algorithm", "-a"], description = "The learning algorithm to use", order = 50)
    var learningAlgorithmType: LearningAlgorithmType = LearningAlgorithmType.TTT
        private set

    @Parameter(names = ["--output-formats", "-o"], description = "The formats of the hypothesis output(s)", order = 51)
    var outputFormats: List<OutputFormat> = listOf(OutputFormat.SERIALIZED, OutputFormat.SIMPLE_VISUALIZATION)
        private set

    @Parameter(names = ["--output-intermediate-hypothesis"], description = "If set, the state learner will not only output the final hypothesis but rather every intermediate hypothesis", order = 52)
    var outputIntermediateHypothesis: Boolean = false
        private set

    @Parameter(names = ["--equiv-oracle-chain"], description = "The equivalence oracle chain to use (comma-separated combination of CACHE_CONSISTENCY, HAPPY_FLOW, COMPLETE_EXPLORATION, RANDOM_WORDS, RANDOM_WALK, RANDOM_W, RANDOM_WP, W, WP)", listConverter = EQOracleChainSplitter::class, order = 100)
    var equivOracleChainTypes: List<EquivalenceOracleType> = listOf(EquivalenceOracleType.CACHE_CONSISTENCY, EquivalenceOracleType.HAPPY_FLOW, EquivalenceOracleType.RANDOM_WORDS)
        private set

    @Parameter(names = ["--equiv-happy-flow-suffix-length"], description = "[HAPPY_FLOW only] The length of the suffix to append to each possible happy flow prefix", order = 101)
    var equivHappyFlowSuffixLength = EquivalenceOracleFactory.happyFlowSuffixLength
        private set

    @Parameter(names = ["--equiv-complete-exploration-min-depth"], description = "[COMPLETE_EXPLORATION only] The minimum depth to explore (i. e. the minimum length of words tested)", order = 102)
    var equivCompleteExplorationMinDepth = EquivalenceOracleFactory.completeExplorationMinDepth
        private set

    @Parameter(names = ["--equiv-complete-exploration-max-depth"], description = "[COMPLETE_EXPLORATION only] The maximum depth to explore (i. e. the maximum length of words tested)", order = 103)
    var equivCompleteExplorationMaxDepth = EquivalenceOracleFactory.completeExplorationMaxDepth
        private set

    @Parameter(names = ["--equiv-random-words-min-length"], description = "[RANDOM_WORDS only] Minimum length of random words used to test for equivalence of the hypothesis with the real SUL", order = 104)
    var equivRandomWordsMinLength: Int = EquivalenceOracleFactory.randomWordsMinLength
        private set

    @Parameter(names = ["--equiv-random-words-max-length"], description = "[RANDOM_WORDS only] Maximum length of random words used to test for equivalence of the hypothesis with the real SUL", order = 105)
    var equivRandomWordsMaxLength: Int = EquivalenceOracleFactory.randomWordsMaxLength
        private set

    @Parameter(names = ["--equiv-random-words-max-tests"], description = "[RANDOM_WORDS only] Maximum number of random words to test before hypothesis and real SUL are considered equivalent", order = 106)
    var equivRandomWordsMaxTests: Int = EquivalenceOracleFactory.randomWordsMaxTests
        private set

    @Parameter(names = ["--equiv-random-walk-reset-prob"], description = "[RANDOM_WALK only] The probability that the walk is restarted after a step", order = 107)
    var equivRandomWalkResetProbability: Double = EquivalenceOracleFactory.randomWalkRestartProbability
        private set

    @Parameter(names = ["--equiv-random-walk-max-steps"], description = "[RANDOM_WALK only] Maximum number of steps to walk before hypothesis and SUL are considered equal", order = 108)
    var equivRandomWalkMaxSteps: Long = EquivalenceOracleFactory.randomWalkMaxSteps
        private set

    @Parameter(names = ["--equiv-w-max-depth"], description = "[W / WP only] The maximum length of the \"middle\" part of all words generated", order = 109)
    var equivWMaxDepth: Int = EquivalenceOracleFactory.wMaxDepth
        private set

    @Parameter(names = ["--equiv-random-w-minimal-size"], description = "[RANDOM_W / RANDOM_WP only] The minimal size of a random word", order = 110)
    var equivRandomWMinimalSize: Int = EquivalenceOracleFactory.randomWMinimalSize
        private set

    @Parameter(names = ["--equiv-random-w-rnd-length"], description = "[RANDOM_W / RANDOM_WP only] The expected length of a random word. The effective expected length is minimal size + rnd length", order = 111)
    var equivRandomWRndLength: Int = EquivalenceOracleFactory.randomWRndLength
        private set

    @Parameter(names = ["--equiv-random-w-bound"], description = "[RANDOM_W / RANDOM_WP only] The maximum number of words to test before hypothesis and SUL are considered equal. If this oracle is configured to be unbounded (bound = 0), it does not terminate if the hypothesis is correct", order = 112)
    var equivRandomWBound: Int = EquivalenceOracleFactory.randomWBound
        private set
}
