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
import de.rub.nds.sshstatelearner.algorithms.EquivalenceOracleType
import de.rub.nds.sshstatelearner.algorithms.LearningAlgorithmType

object ArgsLearner {
    @Parameter(names = ["--algorithm", "-a"], description = "The learning algorithm to use", order = 50)
    var learningAlgorithmType: LearningAlgorithmType = LearningAlgorithmType.TTT
        private set

    @Parameter(names = ["--equiv-oracle-type"], description = "The equivalence oracle type to use", order = 100)
    var equivOracleType: EquivalenceOracleType = EquivalenceOracleType.RANDOM_WORDS
        private set

    @Parameter(names = ["--equiv-complete-exploration-min-depth"], description = "[COMPLETE_EXPLORATION only] The minimum depth to explore (i. e. the minimum length of words tested)", order = 101)
    var equivCompleteExplorationMinDepth = EquivalenceOracleType.completeExplorationMinDepth
        private set

    @Parameter(names = ["--equiv-complete-exploration-max-depth"], description = "[COMPLETE_EXPLORATION only] The maximum depth to explore (i. e. the maximum length of words tested)", order = 102)
    var equivCompleteExplorationMaxDepth = EquivalenceOracleType.completeExplorationMaxDepth
        private set

    @Parameter(names = ["--equiv-random-words-min-length"], description = "[RANDOM_WORDS only] Minimum length of random words used to test for equivalence of the hypothesis with the real SUL", order = 103)
    var equivRandomWordsMinLength: Int = EquivalenceOracleType.randomWordsMinLength
        private set

    @Parameter(names = ["--equiv-random-words-max-length"], description = "[RANDOM_WORDS only] Maximum length of random words used to test for equivalence of the hypothesis with the real SUL", order = 104)
    var equivRandomWordsMaxLength: Int = EquivalenceOracleType.randomWordsMaxLength
        private set

    @Parameter(names = ["--equiv-random-words-max-tests"], description = "[RANDOM_WORDS only] Maximum number of random words to test before hypothesis and real SUL are considered equivalent", order = 105)
    var equivRandomWordsMaxTests: Int = EquivalenceOracleType.randomWordsMaxTests
        private set

    @Parameter(names = ["--equiv-random-walk-reset-prob"], description = "[RANDOM_WALK only] The probability that the walk is restarted after a step", order = 106)
    var equivRandomWalkResetProbability: Double = EquivalenceOracleType.randomWalkRestartProbability
        private set

    @Parameter(names = ["--equiv-random-walk-max-steps"], description = "[RANDOM_WALK only] Maximum number of steps to walk before hypothesis and SUL are considered equal", order = 107)
    var equivRandomWalkMaxSteps: Long = EquivalenceOracleType.randomWalkMaxSteps
        private set

    @Parameter(names = ["--equiv-w-max-depth"], description = "[W / WP only] The maximum length of the \"middle\" part of all words generated", order = 108)
    var equivWMaxDepth: Int = EquivalenceOracleType.wMaxDepth
        private set

    @Parameter(names = ["--equiv-random-w-minimal-size"], description = "[RANDOM_W / RANDOM_WP only] The minimal size of a random word", order = 109)
    var equivRandomWMinimalSize: Int = EquivalenceOracleType.randomWMinimalSize
        private set

    @Parameter(names = ["--equiv-random-w-rnd-length"], description = "[RANDOM_W / RANDOM_WP only] The expected length of a random word. The effective expected length is minimal size + rnd length", order = 110)
    var equivRandomWRndLength: Int = EquivalenceOracleType.randomWRndLength
        private set

    @Parameter(names = ["--equiv-random-w-bound"], description = "[RANDOM_W / RANDOM_WP only] The maximum number of words to test before hypothesis and SUL are considered equal. If this oracle is configured to be unbounded (bound = 0), it does not terminate if the hypothesis is correct", order = 111)
    var equivRandomWBound: Int = EquivalenceOracleType.randomWBound
        private set
}
