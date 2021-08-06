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
import de.rub.nds.sshstatelearner.algorithms.LearningAlgorithm
import de.rub.nds.sshstatelearner.learner.SshSulLearner

object ArgsLearner {
    @Parameter(names = ["--algorithm"], description = "The learning algorithm to use")
    var learningAlgorithm: LearningAlgorithm = LearningAlgorithm.TTT
        private set

    @Parameter(names = ["--equivRandomWordsMinLength"], description = "Minimum length of random words used to test for equivalence of the hypothesis with the real SUL")
    var equivRandomWordsMinLength: Int = SshSulLearner.DEFAULT_EQUIV_RANDOM_WORDS_MIN_LENGTH
        private set

    @Parameter(names = ["--equivRandomWordsMaxLength"], description = "Maximum length of random words used to test for equivalence of the hypothesis with the real SUL")
    var equivRandomWordsMaxLength: Int = SshSulLearner.DEFAULT_EQUIV_RANDOM_WORDS_MAX_LENGTH
        private set

    @Parameter(names = ["--equivRandomWordsMaxTests"], description = "Maximum number of random words to test before hypothesis and real SUL are considered equivalent")
    var equivRandomWordsMaxTests: Int = SshSulLearner.DEFAULT_EQUIV_RANDOM_WORDS_MAX_TESTS
        private set
}
