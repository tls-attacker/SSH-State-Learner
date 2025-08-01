/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.algorithms

import de.learnlib.filter.cache.LearningCacheOracle
import de.learnlib.oracle.EquivalenceOracle
import de.learnlib.query.DefaultQuery
import de.learnlib.query.Query
import de.learnlib.oracle.ParallelOracle
import de.rub.nds.sshstatelearner.exceptions.CacheConflictException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.MajorityVoteOracle
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState
import net.automatalib.automaton.transducer.MealyMachine
import net.automatalib.word.Word
import net.automatalib.word.WordBuilder
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.util.concurrent.locks.ReentrantReadWriteLock
import kotlin.concurrent.read
import kotlin.concurrent.write

/**
 * A simple tree cache to reduce the number of queries executed on the underlying SUL. Applies further optimization
 * by handling input symbols after a connection was closed.
 *
 * @param delegate Underlying membership oracle that can be queried when the cached information are insufficient to answer the query.
 */
class ParallelResponseTreeCache(
    private val delegate: ParallelOracle<SshSymbol, Word<ResponseFingerprint>>,
    private val cacheConflictMajorityVotes: Int
) : LearningCacheOracle.MealyLearningCacheOracle<SshSymbol, ResponseFingerprint>, ParallelOracle<SshSymbol, Word<ResponseFingerprint>> {

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    /**
     * The root node of the cache tree
     */
    private val root: Node = Node(null, null)

    /**
     * The fingerprint of a closed connection. The cache repeats this fingerprint as output when encountered once.
     * Avoids querying the SUL on known to close connection prefixes.
     */
    private val emptyResponseClosedConnectionFingerprint: ResponseFingerprint =
        ResponseFingerprint(emptyList(), SocketState.CLOSED, false)

    /**
     * A lock to ensure thread safety when reading and writing the cache tree. The lock may be held in read mode
     * by multiple threads simultaneously, but only one thread may hold the lock in write mode.
     */
    private val lock = ReentrantReadWriteLock()

    /**
     * The total number of queries answered by the cache.
     */
    private var totalQueriesAnswered = 0

    /**
     * The number of cache hits.
     */
    private var cacheHits = 0

    /**
     * The cache hit rate, which is the ratio of cache hits to the total number of queries answered by the cache.
     */
    val cacheHitRate: Double
        get() = if (totalQueriesAnswered > 0) cacheHits.toDouble() / totalQueriesAnswered.toDouble() else 0.0

    private val majorityVoteDelegate: MajorityVoteOracle<SshSymbol, ResponseFingerprint> =
        MajorityVoteOracle<SshSymbol, ResponseFingerprint>(delegate, cacheConflictMajorityVotes)

    /**
     * Processes a collection of queries by iterating through the collection and calling answerQuery for each query.
     *
     * @param queries The collection of queries to answer.
     */
    override fun processQueries(queries: MutableCollection<out Query<SshSymbol, Word<ResponseFingerprint>>>) {
        val uncachedQueries: MutableList<CacheUpdateQuery> = mutableListOf()
        // First, answer all queries that can be answered from cache alone
        for (query in queries) {
            val cachedResponse = find(query.prefix, query.suffix)
            if (cachedResponse != null) {
                query.answer(cachedResponse)
                totalQueriesAnswered++
                cacheHits++
            } else {
                uncachedQueries.add(CacheUpdateQuery(query))
            }
        }
        // Batch process all queries that are not present in the cache.
        // The cache will be updated with the output of the nested query by the CacheUpdateQuery.
        delegate.processQueries(uncachedQueries)
        // Check for cache conflicts and throw an exception if necessary
        val cacheConflict = uncachedQueries.firstOrNull { it.cacheConflict != null }?.cacheConflict
        if (cacheConflict != null) {
            throw cacheConflict
        }
        totalQueriesAnswered += uncachedQueries.size
    }

    /**
     * Answers a single query by checking if the query is already present in the cache tree. This method will
     * always use the first delegate to answer the query if the cache does not contain the answer.
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
            totalQueriesAnswered++
            cacheHits++
            return cachedResponse
        }
        val delegateResponse = delegate.answerQuery(prefix, suffix)
        totalQueriesAnswered++
        return update(prefix, suffix, delegateResponse)
    }

    /**
     * Searches for a query in the cache tree. If the cached information is sufficient to answer the query, the
     * resulting word is returned. If not, null is returned. This function is thread-safe.
     *
     * @param prefix The prefix of the query.
     * @param suffix The suffix of the query.
     * @return The resulting word if the cached information is sufficient, null otherwise.
     */
    private fun find(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>): Word<ResponseFingerprint>? {
        lock.read {
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
    }

    /**
     * Updates the cache tree by inserting the provided query with its output. If the query conflicts with
     * the stored information, a ConflictException is thrown. This function is thread-safe.
     *
     * @param prefix The prefix of the query.
     * @param suffix The suffix of the query.
     * @param output The output word of the automaton when execution the suffix.
     * @param force If true, the cache will be updated even if the provided output conflicts with the stored information.
     *
     * @return The output word of the automaton when executing the suffix. The return value can differ from the provided output
     *         if the cache was updated with a different output due to a conflict. Only the return value of this method
     *         should be used to answer the query, as it is guaranteed to be consistent with the cache tree.
     *
     * @throws CacheConflictException Thrown when the provided query and output and the stored information are inconsistent
     *                           with each other and a majority vote conflicts with the stored information.
     */
    fun update(prefix: Word<SshSymbol>,
               suffix: Word<SshSymbol>,
               output: Word<ResponseFingerprint>,
               force: Boolean = false,
               isMajorityVoted: Boolean = false) : Word<ResponseFingerprint> {
        lock.write {
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
                    if (isMajorityVoted) {
                        LOGGER.info("Cache conflict resolved by majority vote, returning majority voted response")
                    }
                    return output
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
                        if (!isMajorityVoted) {
                            // The cache conflict may be resolved by a majority vote, so we delegate the query to the majority vote oracle
                            // and update the cache with the majority vote result. If the majority vote oracle returns a conflicting response, we throw an exception.
                            // If the majority vote oracle returns a consistent response, we update the cache with the majority vote result.
                            // This allows us to resolve conflicts without throwing an exception in cases where the update is called with a
                            // conflicting response but the cache contains the majority voted response, while still allowing the user to forcefully update the cache.
                            LOGGER.info("Possible cache conflict detected, delegating to majority vote oracle")
                            val majorityResponse = majorityVoteDelegate.answerQuery(prefix, suffix)
                            return update(prefix, suffix, majorityResponse, isMajorityVoted = true)
                        }
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
                    if (isMajorityVoted) {
                        LOGGER.info("Cache conflict resolved by majority vote, returning majority voted response")
                    }
                    return output
                }
                current = next
            }
            if (isMajorityVoted) {
                LOGGER.info("Cache conflict resolved by majority vote, returning majority voted response")
            }
            return output
        }
    }

    /**
     * Creates a simple cache consistency test to use as an equivalence oracle. Given a hypothesis, all possible
     * tree paths are validated to ensure the hypothesis is consistent with the cached information. This function
     * is thread-safe.
     *
     * @return An equivalence oracle implementation checking the hypothesis against the cache tree.
     */
    override fun createCacheConsistencyTest(): EquivalenceOracle<MealyMachine<*, SshSymbol, *, ResponseFingerprint>, SshSymbol, Word<ResponseFingerprint>> {
        return EquivalenceOracle.MealyEquivalenceOracle { hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>, _: MutableCollection<out SshSymbol> ->
            lock.read {
                return@MealyEquivalenceOracle root.checkHypothesisConsistency(hypothesis, Word.epsilon(), Word.epsilon())
            }
        }
    }

    /**
     * Shuts down the delegate oracle.
     */
    override fun shutdown() {
        delegate.shutdown()
    }

    /**
     * Shuts down the delegate oracle and cancels all pending queries.
     */
    override fun shutdownNow() {
        delegate.shutdownNow()
    }

    /**
     * A nested class representing a single node within the cache tree. It stores the symbol that lead to the node
     * as well as the output of the SUL when executing the symbol.
     *
     * @param inputSymbol The symbol that lead to the node.
     * @param outputSymbol The output of the SUL when executing the symbol.
     */
    private inner class Node(
        val inputSymbol: SshSymbol?,
        var outputSymbol: ResponseFingerprint?
    ) {
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
        fun checkHypothesisConsistency(
            hypothesis: MealyMachine<*, SshSymbol, *, ResponseFingerprint>,
            inputPrefix: Word<SshSymbol>,
            outputPrefix: Word<ResponseFingerprint>
        ): DefaultQuery<SshSymbol, Word<ResponseFingerprint>>? {
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

    /**
     * An oracle query that updates the cache tree with the output of the nested query.
     * The nested query is answered after the cache tree was updated.
     */
    private inner class CacheUpdateQuery(
        private val nestedQuery: Query<SshSymbol, Word<ResponseFingerprint>>
    ) : Query<SshSymbol, Word<ResponseFingerprint>>() {

        override fun answer(output: Word<ResponseFingerprint>) {
            try {
                nestedQuery.answer(this@ParallelResponseTreeCache.update(prefix, suffix, output))
            } catch (e: CacheConflictException) {
                cacheConflict = e
            }
        }

        override fun getPrefix(): Word<SshSymbol> = nestedQuery.prefix

        override fun getSuffix(): Word<SshSymbol> = nestedQuery.suffix

        var cacheConflict: CacheConflictException? = null
    }
}
