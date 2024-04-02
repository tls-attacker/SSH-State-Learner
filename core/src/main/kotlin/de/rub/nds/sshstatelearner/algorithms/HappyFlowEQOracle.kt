/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms

import de.learnlib.api.oracle.EquivalenceOracle
import de.learnlib.api.oracle.MembershipOracle
import de.learnlib.api.query.DefaultQuery
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.extraction.HappyFlowFactory
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.util.combinations
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.words.Word

/**
 * A simple equivalence oracle that checks if equivalence holds for a predefined happy flow (and each of its prefixes)
 * with random suffixes of configurable length. The happy flow is constructed using the HappyFlowFactory.
 *
 * @param membershipOracle The membership oracle representing the SUL to learn.
 * @param stage The protocol stage to check equivalence for.
 * @param kex The key exchange algorithm to check equivalence for.
 * @param suffixLength The length of the randomly generated suffix.
 */
class HappyFlowEQOracle(
    private val membershipOracle: MembershipOracle<SshSymbol, Word<ResponseFingerprint>>,
    private val stage: ProtocolStage,
    private val kex: KeyExchangeAlgorithm,
    private val suffixLength: Int
) : EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {
    /**
     * Searches for a counter example to disprove the hypothesis by iterating all prefixes of the happy flow
     * and combining it with random suffixes.
     *
     * @param hypothesis The hypothesis to check equivalence with the provided membership oracle.
     * @param alphabet The alphabet to check equivalence for.
     * @return A counter example to the hypothesis or null, if no counter example was found.
     */
    override fun findCounterExample(
        hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>,
        alphabet: MutableCollection<out SshSymbol>
    ): DefaultQuery<SshSymbol, Word<ResponseFingerprint>>? {
        val happyFlowPrefixes =
            HappyFlowFactory.constructHappyFlow(stage, kex, ArgsSul.sulTyp.isClientAlphabet).prefixes(true)
        for (prefix in happyFlowPrefixes) {
            val suffixes = alphabet.combinations(suffixLength).map { Word.fromList(it) }
            for (suffix in suffixes) {
                val input = Word.fromWords(prefix, suffix)
                val sulOutput = membershipOracle.answerQuery(input)
                val hypothesisOutput = hypothesis.computeOutput(input)
                sulOutput.zip(hypothesisOutput).forEach {
                    if (it.first != it.second) {
                        return DefaultQuery(input, sulOutput)
                    }
                }
            }
        }
        return null
    }
}
