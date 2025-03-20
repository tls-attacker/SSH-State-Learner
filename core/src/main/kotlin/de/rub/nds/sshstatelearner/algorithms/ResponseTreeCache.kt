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
import de.learnlib.query.Query
import de.learnlib.filter.cache.LearningCacheOracle
import de.rub.nds.sshstatelearner.analysis.limiter.EmptySMLLimiter
import de.rub.nds.sshstatelearner.analysis.limiter.SMLLimiter
import de.rub.nds.sshstatelearner.analysis.limiter.SMLRun
import de.rub.nds.sshstatelearner.analysis.limiter.message.NotInStateMachineLearningFocusMessage
import de.rub.nds.sshstatelearner.db.QueryResultManager
import de.rub.nds.sshstatelearner.exceptions.CacheConflictException
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import net.automatalib.automaton.transducer.MealyMachine
import net.automatalib.word.Word
import net.automatalib.word.WordBuilder
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger


/**
 * A simple tree cache to reduce the number of queries executed on the underlying SUL. Applies further optimization
 * by handling input symbols after a connection was closed.
 *
 * @param delegates An underlying membership oracle that is queried when the cached information are insufficient to answer the query.
 */
class ResponseTreeCache(
    private val delegates: List<MembershipOracle.MealyMembershipOracle<SshSymbol, ResponseFingerprint>>,
    smlLimiter: SMLLimiter,
    private val repeatedQueriesDuringLearningWithMajorityCount: Int,
    private val queryResultManager: QueryResultManager? = null
) : LearningCacheOracle.MealyLearningCacheOracle<SshSymbol, ResponseFingerprint> {

    constructor(delegate: MembershipOracle.MealyMembershipOracle<SshSymbol, ResponseFingerprint>) : this(
        listOf(delegate),
        EmptySMLLimiter(),
        1
    )

    companion object {
        val logger: Logger = LogManager.getLogger()
    }

    /**
     * The root node of the cache tree
     */
    private val root: Node = Node(null, null)

    private val smlLimiter: SMLLimiter = smlLimiter.apply { init() }

    /**
     * The fingerprint of a closed connection. The cache repeats this fingerprint as output when encountered once.
     * Avoids querying the SUL on known to close connection prefixes.
     */
    private val emptyResponseClosedConnectionFingerprint: ResponseFingerprint =
        ResponseFingerprint(emptyList(), SocketState.CLOSED)

    /**
     * The fingerprint is used if the DFA limits the input alphabet.
     */
    private val notInStateMachineLearningFocusWithSocketClosed =
        ResponseFingerprint(listOf(NotInStateMachineLearningFocusMessage()), SocketState.CLOSED)

    /**
     * Processes a collection of queries by iterating through the collection and calling answerQuery for each query.
     *
     * @param queries The collection of queries to answer.
     */
    override fun processQueries(queries: MutableCollection<out Query<SshSymbol, Word<ResponseFingerprint>>>) {
        fun processOneQuery(
            query: Query<SshSymbol, Word<ResponseFingerprint>>,
            delegateIndex: Int,
            cacheIndex: Int,
            pairOfQueriesAndResponsesToUpdateToCache: Array<Pair<Query<SshSymbol, Word<ResponseFingerprint>>, Word<ResponseFingerprint>>?>
        ) {
            val cachedResponse = find(query.prefix, query.suffix)
            if (cachedResponse.wordResponseFingerprint != null) {
                query.answer(cachedResponse.wordResponseFingerprint)
                return
            }

            val smlLimiterResponse = analysisInputWithSmlLimiter(
                query.prefix,
                query.suffix,
                delegates[delegateIndex]
            )

            val response = smlLimiterResponse ?: answerQueryWithSul(
                query.prefix,
                query.suffix,
                delegates[delegateIndex]
            )

            pairOfQueriesAndResponsesToUpdateToCache[cacheIndex] = Pair(query, response)
        }

        /**
         * Updates the cache
         */
        fun processQueryAnswerAndUpdate(pairOfQueriesAndResponsesToUpdateToCache: Array<Pair<Query<SshSymbol, Word<ResponseFingerprint>>, Word<ResponseFingerprint>>?>) {
            pairOfQueriesAndResponsesToUpdateToCache.filterNotNull()
                .forEach {
                    val query = it.first
                    var answer = it.second
                    if (isQueryValidInCacheContext(query.prefix, query.suffix, answer)) {
                        update(query.prefix, query.suffix, answer)
                    } else {
                        answer = answerQueryWithMajorityVote(query.prefix, query.suffix)
                        overwrite(query.prefix, query.suffix, answer)
                    }
                    query.answer(answer)
                }
        }


        runBlocking {
            val jobs = mutableListOf<Job>()
            val iterator = queries.iterator().withIndex()
            val pairOfQueriesAndResponsesToUpdateToCache: Array<Pair<Query<SshSymbol, Word<ResponseFingerprint>>, Word<ResponseFingerprint>>?> =
                arrayOfNulls(queries.size)
            val mutex = Mutex()
            // Each thread independently retrieves the query that it then processes.
            for (delegateIndex in delegates.indices) {
                jobs.add(
                    launch(Dispatchers.IO) {
                        while (true) {
                            val element = mutex.withLock {
                                if (iterator.hasNext()) {
                                    iterator.next()
                                } else return@launch
                            }
                            processOneQuery(
                                element.value,
                                delegateIndex,
                                element.index,
                                pairOfQueriesAndResponsesToUpdateToCache
                            )
                        }
                    }
                )
            }

            joinAll(*jobs.toTypedArray())
            processQueryAnswerAndUpdate(pairOfQueriesAndResponsesToUpdateToCache)
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
    override fun answerQuery(
        prefix: Word<SshSymbol>,
        suffix: Word<SshSymbol>
    ): Word<ResponseFingerprint> {
        val cachedResponse = find(prefix, suffix)
        if (cachedResponse.wordResponseFingerprint != null) {
            return cachedResponse.wordResponseFingerprint
        }

        val smlLimiterResponse =
            analysisInputWithSmlLimiter(prefix, suffix)
        val response = smlLimiterResponse ?: answerQueryWithMajorityVote(prefix, suffix)
        update(prefix, suffix, response)
        return response
    }

    private fun answerQueryWithSul(
        prefix: Word<SshSymbol>,
        suffix: Word<SshSymbol>,
        delegate: MembershipOracle.MealyMembershipOracle<SshSymbol, ResponseFingerprint>
    ): Word<ResponseFingerprint> {
        val answer = delegate.answerQuery(prefix, suffix)
        queryResultManager?.addDBQueryResult(prefix, suffix, answer)
        return answer
    }

    /**
     * Executes a majority voting query
     */
    fun answerQueryWithMajorityVote(
        prefix: Word<SshSymbol>,
        suffix: Word<SshSymbol>,
        overrideMajorityCount: Int? = null
    ): Word<ResponseFingerprint> {
        val listOfAnswers: MutableList<Word<ResponseFingerprint>> = mutableListOf()
        val batchOfAnswers: Array<Word<ResponseFingerprint>?> = arrayOfNulls(delegates.size)


        var majorityCount = repeatedQueriesDuringLearningWithMajorityCount
        if (overrideMajorityCount != null) {
            majorityCount = overrideMajorityCount
        }

        // Concurrent query retrieval
        var currentIndex = 0
        while (currentIndex < majorityCount) {
            runBlocking {
                for (currentDelegateIndex in delegates.indices) {
                    if (currentIndex >= majorityCount) break
                    launch(Dispatchers.IO) {
                        batchOfAnswers[currentDelegateIndex] = if (smlLimiter is EmptySMLLimiter) {
                            answerQueryWithSul(prefix, suffix, delegates[currentDelegateIndex])
                        } else {
                            analysisInputWithSmlLimiter(prefix, suffix, delegates[currentDelegateIndex], true)
                                ?: answerQueryWithSul(prefix, suffix, delegates[currentDelegateIndex])
                        }
                    }
                    currentIndex++
                }
            }
            listOfAnswers.addAll(batchOfAnswers.filterNotNull())
            batchOfAnswers.fill(null)
        }

        // Finds the answer with the most votes
        val setOfAnswers = HashSet(listOfAnswers)
        return setOfAnswers.maxWithOrNull { selector1, selector2 ->
            listOfAnswers.count { predicate -> selector1 == predicate } compareTo
                    listOfAnswers.count { predicate -> selector2 == predicate }
        }?.suffix(suffix.length()) ?: throw IllegalStateException("Empty Answers!")
    }

    /**
     * Analyzes prefix and suffix and thus limits the SUL.
     */
    fun analysisInputWithSmlLimiter(
        prefix: Word<SshSymbol>,
        suffix: Word<SshSymbol>,
        delegate: MembershipOracle.MealyMembershipOracle<SshSymbol, ResponseFingerprint>? = null,
        disableCachedAnswer: Boolean = false
    ): Word<ResponseFingerprint>? {
        val smlRun: SMLRun = smlLimiter.createSMLRun()

        fun generateResponseWithOneNotAllowedAndThenSuffixLengthSocketClosed(suffix: Word<SshSymbol>):
                Word<ResponseFingerprint> =
            WordBuilder<ResponseFingerprint>().append(notInStateMachineLearningFocusWithSocketClosed)
                .repeatAppend(suffix.length() - 1, emptyResponseClosedConnectionFingerprint)
                .toWord()

        fun generateResponseWithSuffixLengthSocketClosed(suffix: Word<SshSymbol>): Word<ResponseFingerprint> =
            WordBuilder<ResponseFingerprint>().repeatAppend(suffix.length(), emptyResponseClosedConnectionFingerprint)
                .toWord()

        fun isAnalysisDFAForPrefixValid(prefix: Word<SshSymbol>): Boolean =
            prefix.none { inputSymbol -> !smlRun.step(inputSymbol) }

        fun isAnalysisDFAForSuffixValid(suffix: Word<SshSymbol>): Boolean =
            isAnalysisDFAForPrefixValid(suffix)

        fun getValidAndInvalidPartOfSuffix(suffix: Word<SshSymbol>): Pair<Word<SshSymbol>, Word<SshSymbol>> {
            val validSuffix = WordBuilder<SshSymbol>()
            val invalidSuffix = WordBuilder<SshSymbol>()
            for (suffixElement in suffix) {
                if (smlRun.step(suffixElement)) {
                    validSuffix.add(suffixElement)
                } else {
                    invalidSuffix.add(suffixElement)
                }
            }
            return Pair(validSuffix.toWord(), invalidSuffix.toWord())
        }


        if (!isAnalysisDFAForPrefixValid(prefix)) return generateResponseWithSuffixLengthSocketClosed(suffix)

        smlRun.saveState()
        return if (isAnalysisDFAForSuffixValid(suffix)) null
        else {
            smlRun.restoreState()
            val validAndInvalidPartOfSuffix = getValidAndInvalidPartOfSuffix(suffix)
            val validPartOfSuffix = validAndInvalidPartOfSuffix.first
            val invalidPartOfSuffix = validAndInvalidPartOfSuffix.second

            val cachedAnswer =
                if (disableCachedAnswer) CachedAnswer(null, false) else this.find(prefix, validPartOfSuffix)
            val cachedResponseFingerprint = cachedAnswer.wordResponseFingerprint
            val response = if (delegate != null) {
                // If a delegate is present use it.
                cachedResponseFingerprint ?: answerQueryWithSul(prefix, validPartOfSuffix, delegate)
            } else {
                if (cachedResponseFingerprint != null && cachedAnswer.isMajorityProved) {
                    // Only majority verified responses are returned.
                    cachedResponseFingerprint
                } else {
                    // starts a query with majority vote
                    answerQueryWithMajorityVote(prefix, validPartOfSuffix)
                }
            }

            if (response.any { it.socketState == SocketState.CLOSED }
            ) {
                // Case socket was closed before
                response.concat(generateResponseWithSuffixLengthSocketClosed(invalidPartOfSuffix))
            } else {
                // Case socket was not closed before
                response.concat(
                    generateResponseWithOneNotAllowedAndThenSuffixLengthSocketClosed(invalidPartOfSuffix)
                )
            }

        }
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
    fun find(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>): CachedAnswer {
        var current: Node? = root
        // Descend the tree according to prefix without recording fingerprints
        for (prefixSymbol in prefix) {
            current = current?.findChild(prefixSymbol)
            if (current?.outputSymbol == null) {
                // The tree does not contain the answer to the query
                return CachedAnswer(null, false)
            } else if (current.isConnectionClosedLeaf()) {
                // We encountered a connection closed leaf during prefix descend phase, answer query directly
                return CachedAnswer(
                    WordBuilder<ResponseFingerprint>().repeatAppend(
                        suffix.length(),
                        emptyResponseClosedConnectionFingerprint
                    ).toWord(), current.isMajorityProved
                )
            }
        }
        // Descend the tree further according to the suffix and record the fingerprints
        val outputBuilder = WordBuilder<ResponseFingerprint>()
        for (suffixSymbolIndex in 0 until suffix.length()) {
            val suffixSymbol = suffix.getSymbol(suffixSymbolIndex)
            if (current?.isConnectionClosedLeaf() == true) {
                return CachedAnswer(
                    outputBuilder.repeatAppend(
                        suffix.length() - suffixSymbolIndex,
                        emptyResponseClosedConnectionFingerprint
                    ).toWord(), current.isMajorityProved
                )
            } else {
                current = current?.findChild(suffixSymbol)
                if (current?.outputSymbol == null) {
                    // The tree does not contain the answer to the query
                    return CachedAnswer(null, false)
                }
                outputBuilder.append(current.outputSymbol)
            }
        }
        return CachedAnswer(outputBuilder.toWord(), current?.isMajorityProved ?: false)

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
    fun update(
        prefix: Word<SshSymbol>,
        suffix: Word<SshSymbol>,
        output: Word<ResponseFingerprint>,
        force: Boolean = false
    ) {
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
                next = Node(suffixSymbol, outputSymbol, force)
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
            if (force) {
                next.isMajorityProved = true
            }

            expectedOutput = expectedOutput.append(next.outputSymbol)

            if (next.isConnectionClosedLeaf() && !force) {
                // The next node marks a closed connection, abort if we're not forced to update
                return
            }
            current = next
        }
    }

    fun isQueryValidInCacheContext(
        prefix: Word<SshSymbol>,
        suffix: Word<SshSymbol>,
        responseFingerprint: Word<ResponseFingerprint>
    ): Boolean {
        var currentNode = root
        var nextNode: Node?
        for (prefixSymbol in prefix) {
            nextNode = currentNode.findChild(prefixSymbol)
            if (nextNode == null) {
                return true
            }
            currentNode = nextNode
        }


        for ((index, suffixSymbol) in suffix.withIndex()) {
            nextNode = currentNode.findChild(suffixSymbol)
            if (nextNode == null) {
                return true
            } else {
                currentNode = nextNode

                val currentCachedOutput = currentNode.outputSymbol
                if (currentNode.outputSymbol == null) {
                    continue
                }
                val currentOutput = responseFingerprint.getSymbol(index)

                if (currentOutput != currentCachedOutput) {
                    return false
                }

            }
        }
        return true
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
    private inner class Node(
        val inputSymbol: SshSymbol?,
        var outputSymbol: ResponseFingerprint?,
        var isMajorityProved: Boolean = false
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

    data class CachedAnswer(
        val wordResponseFingerprint: Word<ResponseFingerprint>?,
        val isMajorityProved: Boolean,
    )
}
