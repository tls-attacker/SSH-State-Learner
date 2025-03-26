/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms

import de.learnlib.oracle.EquivalenceOracle
import de.learnlib.oracle.MembershipOracle
import de.learnlib.query.AdaptiveQuery.Response
import de.learnlib.query.DefaultQuery
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.constants.SulType
import de.rub.nds.sshstatelearner.extraction.HappyFlowFactory
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.util.combinations
import de.rub.nds.sshstatelearner.util.combinationsIgnoreOrder
import net.automatalib.automaton.transducer.MealyMachine
import net.automatalib.word.Word

/**
 * A simple equivalence oracle that checks if equivalence holds for a predefined happy flow (and each of its prefixes)
 * with random insertions up to a configurable limit. The happy flow, if null, is constructed using the HappyFlowFactory.
 *
 * @param membershipOracle The membership oracle representing the SUL to learn.
 * @param stage The protocol stage to check equivalence for.
 * @param kex The key exchange algorithm to check equivalence for.
 * @param maxInsertions The maximum number of symbol insertions to check equivalence for.
 * @param sulType The type of the SUL to check equivalence for.
 * @param batchSize The number of queries to process at once by the membership oracle.
 * @param happyFlow The happy flow to check equivalence for. If null, the happy flow is constructed using the HappyFlowFactory.
 */
class HappyFlowEQOracle(
    private val membershipOracle: MembershipOracle<SshSymbol, Word<ResponseFingerprint>>,
    private val stage: ProtocolStage,
    private val kex: KeyExchangeAlgorithm,
    private val maxInsertions: Int,
    private val sulType: SulType,
    private val batchSize: Int = 1,
    happyFlow: Word<SshSymbol>? = null
) : EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {

    private val happyFlow: Word<SshSymbol> =
        happyFlow ?: HappyFlowFactory.constructHappyFlow(sulType, stage, kex)

    private fun provideChunks(alphabet: MutableCollection<out SshSymbol>): List<List<Word<SshSymbol>>> {
        val inputs: MutableList<Word<SshSymbol>> = mutableListOf()
        for (insertions in 0..maxInsertions) {
            if (insertions == 0) {
                inputs.add(happyFlow.subWord(0))
                continue
            }
            for (insertPositions in (0..happyFlow.length()).combinationsIgnoreOrder(insertions)) {
                alphabet.combinations(insertions).forEach {
                    var input = happyFlow.subWord(0)
                    // Iterate over the insert positions in reverse order to insert the symbols at the correct positions
                    // Insert positions are ordered in ascending order, so we need to reverse the list
                    insertPositions.reversed().forEachIndexed { index, position ->
                        input = if (position < happyFlow.length())
                        // Insert at position: prefix + symbol + suffix
                            input.subWord(0, position).concat(Word.fromSymbols(it[index])).concat(happyFlow.subWord(position))
                        else
                        // Insert at the end: input + symbol
                            input.concat(Word.fromSymbols(it[index]))
                    }
                    inputs.add(input)
                }
            }
        }
        return inputs.chunked(batchSize)
    }

    /**
     * Searches for a counter example to disprove the hypothesis by iterating all possible symbol insertions
     * into a defined happy flow.
     *
     * @param hypothesis The hypothesis to check equivalence with the provided membership oracle.
     * @param alphabet The alphabet to check equivalence for.
     * @return A counter example to the hypothesis or null, if no counter example was found.
     */
    override fun findCounterExample(
        hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>,
        alphabet: MutableCollection<out SshSymbol>
    ): DefaultQuery<SshSymbol, Word<ResponseFingerprint>>? {
        for (chunk in provideChunks(alphabet)) {
            val queries = chunk.map { DefaultQuery<SshSymbol, Word<ResponseFingerprint>>(it) }
            membershipOracle.processQueries(queries)
            queries.forEach {
                val hypothesisOutput = hypothesis.computeOutput(it.input)
                if (!it.output.equals(hypothesisOutput)) {
                    return it
                }
            }
        }
        return null
    }
}
