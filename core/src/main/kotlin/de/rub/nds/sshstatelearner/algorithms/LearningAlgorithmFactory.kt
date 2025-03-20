/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms

import de.learnlib.algorithm.dhc.mealy.MealyDHCBuilder
import de.learnlib.algorithm.kv.mealy.KearnsVaziraniMealyBuilder
import de.learnlib.algorithm.lstar.mealy.ExtensibleLStarMealyBuilder
import de.learnlib.algorithm.ttt.mealy.TTTLearnerMealyBuilder
import de.learnlib.algorithm.LearningAlgorithm
import de.learnlib.algorithm.adt.learner.ADTLearnerBuilder
import de.learnlib.oracle.MembershipOracle
import de.rub.nds.sshstatelearner.constants.LearningAlgorithmType
import net.automatalib.alphabet.Alphabet

/**
 * This object is capable of creating learning algorithm instances via the create method.
 */
object LearningAlgorithmFactory {
    /**
     * Creates a learning algorithm instance specified by the algorithm parameter.
     *
     * @param algorithm The algorithm of the learning algorithm instance.
     * @param alphabet The alphabet to use with the learning algorithm.
     * @param membershipOracle The membership oracle representing the SUL to learn.
     * @return An instance of a learning algorithm specified by the algorithm parameter seeded
     *         with the provided alphabet and oracle.
     */
    fun <I, O> create(
        algorithm: LearningAlgorithmType,
        alphabet: Alphabet<I>,
        membershipOracle: MembershipOracle.MealyMembershipOracle<I, O>
    ): LearningAlgorithm.MealyLearner<I, O> {
        return when (algorithm) {
            LearningAlgorithmType.DHC -> MealyDHCBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
            LearningAlgorithmType.KV -> KearnsVaziraniMealyBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
            LearningAlgorithmType.LSTAR -> ExtensibleLStarMealyBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
            LearningAlgorithmType.TTT -> TTTLearnerMealyBuilder<I, O>()
                .withAlphabet(alphabet)
                .withOracle(membershipOracle)
                .create()
        }
    }
}
