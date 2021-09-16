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
import de.learnlib.api.query.Query
import de.learnlib.filter.cache.LearningCacheOracle
import de.rub.nds.sshstatelearner.exceptions.CacheConflictException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.words.Word
import net.automatalib.words.WordBuilder

/**
 * A simple tree cache to reduce the number of queries executed on the underlying SUL. Applies further optimization
 * by handling input symbols after a connection was closed.
 *
 * @param delegate An underlying membership oracle that is queried when the cached information are insufficient to answer the query.
 */
class ResponseTreeCache(
    private val delegate: MembershipOracle.MealyMembershipOracle<SshSymbol, ResponseFingerprint>
) : LearningCacheOracle.MealyLearningCacheOracle<SshSymbol, ResponseFingerprint> {

    /**
     * The root node of the cache tree
     */
    private val root: Node = Node(null, null)

    /**
     * The fingerprint of a closed connection. The cache repeats this fingerprint as output when encountered once.
     * Avoids querying the SUL on known to close connection prefixes.
     */
    private val emptyResponseClosedConnectionFingerprint: ResponseFingerprint = ResponseFingerprint(emptyList(), SocketState.CLOSED)

    /**
     * Processes a collection of queries by iterating through the collection and calling answerQuery for each query.
     *
     * @param queries The collection of queries to answer.
     */
    override fun processQueries(queries: MutableCollection<out Query<SshSymbol, Word<ResponseFingerprint>>>) {
        for (query in queries) {
            val output = answerQuery(query.prefix, query.suffix)
            query.answer(output)
        }
    }

    /**
     * Answers a single query by checking if the query is already present in the cache tree.
     *
     * @param prefix The prefix of the query. If a symbol is part of the prefix, it is executed on the automaton but
     *               its output is not contained within the query answer.
     * @param suffix The suffix of the query.
     * @return The output of the mealy machine when executing prefix and suffix. Only the output of the suffix symbols
     *         is returned.
     */
    override fun answerQuery(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>): Word<ResponseFingerprint> {
        val cachedResponse = find(prefix, suffix)
        if (cachedResponse != null) {
            return cachedResponse
        }
        val delegateResponse = delegate.answerQuery(prefix, suffix)
        update(prefix, suffix, delegateResponse)
        return delegateResponse
    }

    /**
     *
     */
    fun overwrite(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>, output: Word<ResponseFingerprint>) =
        update(prefix, suffix, output, true)

    /**
     * Searches for a query in the cache tree. If the cached information is sufficient to answer the query, the
     * resulting word is returned. If not, null is returned.
     *
     * @param prefix The prefix of the query.
     * @param suffix The suffix of the query.
     * @return The resulting word if the cached information is sufficient, null otherwise.
     */
    private fun find(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>): Word<ResponseFingerprint>? {
        var current: Node? = root
        // Descend the tree according to prefix without recording fingerprints
        for (prefixSymbol in prefix) {
            current = current?.findChild(prefixSymbol)
            if (current?.outputSymbol == null) {
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
                if (current?.outputSymbol == null) {
                    // The tree does not contain the answer to the query
                    return null
                }
                outputBuilder.append(current.outputSymbol)
            }
        }
        return outputBuilder.toWord()
    }

    /**
     * Updates the cache tree by inserting the provided query with its output. If the query conflicts with
     * the stored information, a ConflictException is thrown.
     *
     * @param prefix The prefix of the query.
     * @param suffix The suffix of the query.
     * @param output The output word of the automaton when execution the suffix.
     *
     * @throws CacheConflictException Thrown when the provided query and output and the stored information are inconsistent
     *                           with each other.
     */
    private fun update(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>, output: Word<ResponseFingerprint>, force: Boolean = false) {
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
            if (next.isConnectionClosedLeaf() && !force) {
                // The next nodes marks a closed connection, abort if we're not forced to update
                return
            }
            current = next
        }
        // Descend the tree according to the suffix and create nodes with their corresponding response fingerprint
        var expectedOutput = Word.epsilon<ResponseFingerprint>()
        for (suffixSymbolIndex in 0 until suffix.length()) {
            val suffixSymbol = suffix.getSymbol(suffixSymbolIndex)
            val outputSymbol = output.getSymbol(suffixSymbolIndex)

            next = current.findChild(suffixSymbol)
            if (next == null) {
                // Node is not yet present in the tree, create a new one
                next = Node(suffixSymbol, outputSymbol)
                current.children.add(next)
            } else if (next.outputSymbol != outputSymbol) {
                // We were asked to update the cache, but the cached information is inconsistent with the provided prefix-suffix / output combination
                // We'll throw an exception if the force parameter is false. If its value is true however, we'll overwrite the cached information and continue.
                if (force) {
                    next.outputSymbol = outputSymbol
                } else {
                    throw CacheConflictException(
                        "Unable to update tree node non-forcefully, conflicting response fingerprints for same node: $outputSymbol | ${next.outputSymbol}",
                        prefix,
                        suffix.prefix(suffixSymbolIndex + 1),
                        expectedOutput.append(next.outputSymbol),
                        output.prefix(suffixSymbolIndex + 1)
                    )
                }
            }
            expectedOutput = expectedOutput.append(next.outputSymbol)
            if (next.isConnectionClosedLeaf() && !force) {
                // The next node marks a closed connection, abort if we're not forced to update
                return
            }
            current = next
        }
    }

    /**
     * Creates a simple cache consistency test to use as an equivalence oracle. Given a hypothesis, all possible
     * tree paths are validated to ensure the hypothesis is consistent with the cached information.
     *
     * @return An equivalence oracle implementation checking the hypothesis against the cache tree.
     */
    override fun createCacheConsistencyTest(): EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {
        return EquivalenceOracle.MealyEquivalenceOracle { hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>, _: MutableCollection<out SshSymbol> ->
            return@MealyEquivalenceOracle root.checkHypothesisConsistency(hypothesis, Word.epsilon(), Word.epsilon())
        }
    }

    /**
     * A nested class representing a single node within the cache tree. It stores the symbol that lead to the node
     * as well as the output of the SUL when executing the symbol.
     *
     * @param inputSymbol The symbol that lead to the node.
     * @param outputSymbol The output of the SUL when executing the symbol.
     */
    private inner class Node(val inputSymbol: SshSymbol?, var outputSymbol: ResponseFingerprint?) {
        /**
         * The list of children nodes that can be reached from this node.
         */
        val children: MutableList<Node> = mutableListOf()

        /**
         * Checks whether this node is a leaf due to the connection being closed.
         *
         * @return True if the fingerprints' socket state indicates a closed connections.
         */
        fun isConnectionClosedLeaf(): Boolean {
            return outputSymbol?.socketState == SocketState.CLOSED
        }

        /**
         * Finds a children node given the input symbol.
         *
         * @param symbol The input symbol.
         * @return The child node storing the output with the provided input symbol. Returns null if such a child node
         *         is not present.
         */
        fun findChild(symbol: SshSymbol): Node? {
            return children.find { it.inputSymbol == symbol }
        }

        /**
         * Checks whether a hypothesis is consistent with the subtree created by this node. If not, it returns a
         * counter example disproving the hypothesis.
         *
         * @param hypothesis The hypothesis to check.
         * @param inputPrefix The input prefix that lead to this node.
         * @param outputPrefix The output prefix produced by the automaton before reaching this node.
         * @return Returns a counter example disproving the hypothesis if such a counter example exists in the subtree
         *         induced by this node. Returns null otherwise.
         */
        fun checkHypothesisConsistency(hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>, inputPrefix: Word<SshSymbol>, outputPrefix: Word<ResponseFingerprint>): DefaultQuery<SshSymbol, Word<ResponseFingerprint>>? {
            if ((inputSymbol == null || outputSymbol == null) && inputPrefix.length() > 0) {
                // Symbol or fingerprint is null and this node is not the root node, unable to check consistency
                return null
            }

            val input = if (inputSymbol != null) inputPrefix.append(inputSymbol) else inputPrefix
            val expectedOutput = if (outputSymbol != null) outputPrefix.append(outputSymbol) else outputPrefix
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

        /**
         * Serializes the node into a short string. This allows for easier debugging and visualization.
         *
         * @return A string representing the node.
         */
        override fun toString(): String {
            return "Node[inputSymbol=$inputSymbol,outputSymbol=$outputSymbol]"
        }
    }
}
