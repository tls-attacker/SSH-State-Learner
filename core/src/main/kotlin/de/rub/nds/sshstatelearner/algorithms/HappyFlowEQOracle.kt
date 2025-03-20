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
import de.learnlib.query.DefaultQuery
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.extraction.HappyFlowFactory
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.ProtocolStage
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
 * @param insertions The maximum number of symbol insertions to check equivalence for.
 * @param isClient True if the oracle is used for a client, false otherwise.
 * @param batchSize The number of queries to process at once by the membership oracle.
 * @param happyFlow The happy flow to check equivalence for. If null, the happy flow is constructed using the HappyFlowFactory.
 */
class HappyFlowEQOracle(
    private val membershipOracle: MembershipOracle<SshSymbol, Word<ResponseFingerprint>>,
    private val stage: ProtocolStage,
    private val kex: KeyExchangeAlgorithm,
    private val insertions: Int,
    isClient: Boolean,
    private val batchSize: Int = 1,
    happyFlow: Word<SshSymbol>? = null
) : EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {

    private val happyFlow: Word<SshSymbol> =
        happyFlow ?: HappyFlowFactory.constructHappyFlow(isClient, stage, kex)

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
        for (insertPositions in (-1 until happyFlow.length() + 1).combinationsIgnoreOrder(insertions)) {
            val inputs = alphabet.combinations(insertions).map {
                var input = happyFlow.subWord(0)
                // Iterate over the insert positions in reverse order to insert the symbols at the correct positions
                // Insert positions are ordered in ascending order, so we need to reverse the list
                insertPositions.reversed().forEachIndexed { index, position ->
                    input = if (position >= 0 && position < happyFlow.length())
                        // Insert at position: prefix + symbol + suffix
                        input.subWord(0, position).concat(Word.fromSymbols(it[index])).concat(happyFlow.subWord(position))
                    else if (position >= happyFlow.length())
                        // Insert at the end: input + symbol
                        input.concat(Word.fromSymbols(it[index]))
                    else
                        // Do not insert the symbol
                        input
                }
                return@map input
            }
            if (batchSize > 1) {
                // Chunk inputs into batches and process them at once by the membership oracle
                val chunks = inputs.map { DefaultQuery<SshSymbol, Word<ResponseFingerprint>>(it) }.chunked(batchSize)
                for (chunk in chunks) {
                    membershipOracle.processBatch(chunk)
                    chunk.forEach {
                        val hypothesisOutput = hypothesis.computeOutput(it.input)
                        if (!it.output.equals(hypothesisOutput)) {
                            return it
                        }
                    }
                }
            } else {
                // Process inputs sequentially by the membership oracle
                for (input in inputs) {
                    val output = membershipOracle.answerQuery(input)
                    val hypothesisOutput = hypothesis.computeOutput(input)
                    if (!output.equals(hypothesisOutput)) {
                        return DefaultQuery(input, output)
                    }
                }
            }
        }
        return null
    }
}
