/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms

import de.learnlib.algorithms.dhc.mealy.MealyDHCBuilder
import de.learnlib.algorithms.discriminationtree.mealy.DTLearnerMealyBuilder
import de.learnlib.algorithms.kv.mealy.KearnsVaziraniMealyBuilder
import de.learnlib.algorithms.lstar.mealy.ExtensibleLStarMealyBuilder
import de.learnlib.algorithms.ttt.mealy.TTTLearnerMealyBuilder
import de.learnlib.api.oracle.MembershipOracle
import net.automatalib.words.Alphabet

open class LearningAlgorithmFactory internal constructor() {
    fun <I, O> create(algorithm: LearningAlgorithm, alphabet: Alphabet<I>, membershipOracle: MembershipOracle.MealyMembershipOracle<I, O>): de.learnlib.api.algorithm.LearningAlgorithm.MealyLearner<I, O> {
        return when (algorithm) {
            LearningAlgorithm.DHC -> MealyDHCBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
            LearningAlgorithm.DT -> DTLearnerMealyBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
            LearningAlgorithm.KV -> KearnsVaziraniMealyBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
            LearningAlgorithm.LSTAR -> ExtensibleLStarMealyBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
            LearningAlgorithm.TTT -> TTTLearnerMealyBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
        }
    }
}
