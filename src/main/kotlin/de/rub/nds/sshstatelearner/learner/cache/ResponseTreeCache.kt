/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.learner.cache

import de.learnlib.api.oracle.EquivalenceOracle
import de.learnlib.api.oracle.MembershipOracle
import de.learnlib.api.query.DefaultQuery
import de.learnlib.api.query.Query
import de.learnlib.filter.cache.LearningCacheOracle
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import de.rub.nds.tlsattacker.transport.socket.SocketState
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.incremental.ConflictException
import net.automatalib.words.Word
import net.automatalib.words.WordBuilder

class ResponseTreeCache(private val delegate: MembershipOracle.MealyMembershipOracle<SshSymbol, ResponseFingerprint>) : LearningCacheOracle.MealyLearningCacheOracle<SshSymbol, ResponseFingerprint> {

    /**
     * The root node of the tree cache
     */
    private val root: Node = Node(null, null)

    /**
     * The fingerprint of a closed connection. The cache repeats this fingerprint as output when encountered once.
     * Avoids querying the SUL on known to close connection prefixes.
     */
    private val emptyResponseClosedConnectionFingerprint: ResponseFingerprint = ResponseFingerprint(emptyList(), SocketState.CLOSED)

    override fun processQueries(queries: MutableCollection<out Query<SshSymbol, Word<ResponseFingerprint>>>) {
        for (query in queries) {
            val output = answerQuery(query.prefix, query.suffix)
            query.answer(output)
        }
    }

    override fun answerQuery(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>): Word<ResponseFingerprint> {
        val cachedResponse = find(prefix, suffix)
        if (cachedResponse != null) {
            return cachedResponse
        }
        val delegateResponse = delegate.answerQuery(prefix, suffix)
        update(prefix, suffix, delegateResponse)
        return delegateResponse
    }

    private fun find(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>): Word<ResponseFingerprint>? {
        var current: Node? = root
        // Descend the tree according to prefix without recording fingerprints
        for (prefixSymbol in prefix) {
            current = current?.findChild(prefixSymbol)
            if (current?.fingerprint == null) {
                // The tree does not contain the answer to the query
                return null
            } else if (current.isConnectionClosedLeaf()) {
                // We encountered a connection closed leaf during prefix descend phase, answer query directly
                return WordBuilder<ResponseFingerprint>().repeatAppend(suffix.length(), emptyResponseClosedConnectionFingerprint)
                    .toWord()
            }
        }
        // Descend the tree further according to the suffix and record the fingerprints
        val outputBuilder = WordBuilder<ResponseFingerprint>()
        for (suffixSymbolIndex in 0 until suffix.length()) {
            val suffixSymbol = suffix.getSymbol(suffixSymbolIndex)
            if (current?.isConnectionClosedLeaf() == true) {
                return outputBuilder.repeatAppend(suffix.length() - suffixSymbolIndex, emptyResponseClosedConnectionFingerprint)
                    .toWord()
            } else {
                current = current?.findChild(suffixSymbol)
                if (current?.fingerprint == null) {
                    // The tree does not contain the answer to the query
                    return null
                }
                outputBuilder.append(current.fingerprint)
            }
        }
        return outputBuilder.toWord()
    }

    private fun update(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>, output: Word<ResponseFingerprint>) {
        var current: Node = root
        var next: Node?
        // Descend the tree according to the prefix and create nodes without response fingerprints if necessary
        for (prefixSymbol in prefix) {
            next = current.findChild(prefixSymbol)
            if (next == null) {
                // Node is not yet present in the tree, create a new one
                next = Node(prefixSymbol, null)
                current.children.add(next)
            }
            if (next.isConnectionClosedLeaf()) {
                // The next nodes marks a closed connection, we do not need to update the tree
                return
            }
            current = next
        }
        // Descend the tree according to the suffix and create nodes with their corresponding response fingerprint
        for (suffixSymbolIndex in 0 until suffix.length()) {
            val suffixSymbol = suffix.getSymbol(suffixSymbolIndex)
            val outputSymbol = output.getSymbol(suffixSymbolIndex)

            next = current.findChild(suffixSymbol)
            if (next == null) {
                // Node is not yet present in the tree, create a new one
                next = Node(suffixSymbol, outputSymbol)
                current.children.add(next)
            } else if (next.fingerprint != outputSymbol) {
                // Should not happen, but just in case we throw an exception
                throw ConflictException("Unable to update tree node, conflicting response fingerprints for same node: $outputSymbol | ${next.fingerprint}")
            }
            if (next.isConnectionClosedLeaf()) {
                // The next node marks a closed connection, we are done updating the tree
                return
            }
            current = next
        }
    }

    override fun createCacheConsistencyTest(): EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {
        return EquivalenceOracle.MealyEquivalenceOracle { hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>, _: MutableCollection<out SshSymbol> ->
            return@MealyEquivalenceOracle root.checkHypothesisConsistency(hypothesis, Word.epsilon(), Word.epsilon())
        }
    }

    private inner class Node(val symbol: SshSymbol?, val fingerprint: ResponseFingerprint?) {
        val children: MutableList<Node> = mutableListOf()

        fun isConnectionClosedLeaf(): Boolean {
            return fingerprint?.socketState == SocketState.CLOSED
        }

        fun findChild(symbol: SshSymbol): Node? {
            return children.find { it.symbol == symbol }
        }

        fun checkHypothesisConsistency(hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>, inputPrefix: Word<SshSymbol>, outputPrefix: Word<ResponseFingerprint>): DefaultQuery<SshSymbol, Word<ResponseFingerprint>>? {
            if ((symbol == null || fingerprint == null) && inputPrefix.length() > 0) {
                // Symbol or fingerprint is null and this node is not the root node, unable to check consistency
                return null
            }

            val input = if (symbol != null) inputPrefix.append(symbol) else inputPrefix
            val expectedOutput = if (fingerprint != null) outputPrefix.append(fingerprint) else outputPrefix
            if (children.size == 0) {
                // The current node is a leaf, compute the output on the current input word and check for consistency
                val hypothesisOutput = hypothesis.computeOutput(input)
                expectedOutput.zip(hypothesisOutput).forEach {
                    if (it.first != it.second) return DefaultQuery(input, expectedOutput)
                }
            } else {
                // The current node is no leaf, recursively descend the cache tree
                for (child in children) {
                    val counterExample = child.checkHypothesisConsistency(hypothesis, input, expectedOutput)
                    if (counterExample != null) {
                        return counterExample
                    }
                }
            }
            return null
        }

        override fun toString(): String {
            return "Node[symbol=$symbol,response=$fingerprint]"
        }
    }
}
