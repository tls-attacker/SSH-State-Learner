/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.learnlib.api.SUL
import de.rub.nds.sshattacker.core.config.Config
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshstatelearner.extraction.HappyFlowFactory
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.words.Word
import net.automatalib.words.WordBuilder
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

abstract class SshSul(
    val name: String,
    val timeout: Long = DEFAULT_SUL_TIMEOUT,
    val resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    val stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    val kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    val strictKex: Boolean = DEFAULT_STRICT_KEX_ENABLED
) : SUL<SshSymbol, ResponseFingerprint>, AutoCloseable {

    /**
     * The config of the SSH-Attacker.
     */
    protected lateinit var config: Config

    /**
     * The state of the SSH-Attacker.
     */
    protected lateinit var state: State

    /**
     * A list of SshSymbols that need to be executed within pre() to reach the defined protocol stage.
     */
    protected val preamble: Word<SshSymbol> = constructPreamble()

    /**
     * A list of all executed steps on the current SSH connection.
     */
    protected val executedSteps = mutableListOf<SshSymbol>()

    /**
     * Whether the SUL is a client or a server.
      */
    protected abstract val isClient: Boolean

    companion object {
        /**
         * Logger for the SshSul class.
         */
        private val LOGGER: Logger = LogManager.getLogger()

        /**
         * A non-negative integer value indicating the timeout for symbol execution.
         */
        const val DEFAULT_SUL_TIMEOUT: Long = 50

        /**
         * A non-negative integer value indicating the delay when resetting the SUL.
         */
        const val DEFAULT_SUL_RESET_DELAY: Long = 0

        /**
         * The default protocol stage to execute on
         */
        val DEFAULT_PROTOCOL_STAGE: ProtocolStage = ProtocolStage.TRANSPORT

        /**
         * The default key exchange algorithm
         */
        val DEFAULT_KEX_ALGORITHM: KeyExchangeAlgorithm = KeyExchangeAlgorithm.ECDH_SHA2_NISTP521

        /**
         * The default value for the strict key exchange protocol extension
         */
        const val DEFAULT_STRICT_KEX_ENABLED: Boolean = false
    }

    /**
     * Constructs a list of SshSymbols that need to be executed to reach the provided SSH protocol stage.
     *
     * @return List of SshSymbols whose execution lead to the provided SSH protocol stage.
     */
    private fun constructPreamble(): Word<SshSymbol> {
        var preamble: Word<SshSymbol> = Word.epsilon()
        if (stage == ProtocolStage.AUTHENTICATION || stage == ProtocolStage.CONNECTION) {
            preamble = preamble.concat(
                HappyFlowFactory.constructHappyFlow(
                    isClient,
                    ProtocolStage.TRANSPORT,
                    kex
                )
            )
        }
        if (stage == ProtocolStage.CONNECTION) {
            preamble = preamble.concat(
                HappyFlowFactory.constructHappyFlow(
                    isClient,
                    ProtocolStage.AUTHENTICATION,
                    kex,
                )
            )
        }
        return preamble
    }

    /**
     * Tear down all stateful components of this SUL.
     */
    override fun post() {
        executedSteps.clear()
    }

    /**
     * Close the SUL and release all resources.
     */
    override fun close() {}

    /**
     * Performs a majority vote on the given prefix and suffix to determine the majority element.
     *
     * @param prefix The prefix to execute before
     * @param suffix The suffix to execute after
     * @param count The number of votes to perform
     * @return The majority element of the votes
     */
    fun majorityVote(prefix: Word<SshSymbol>, suffix: Word<SshSymbol>, count: Int): Word<ResponseFingerprint> {
        val voteList = mutableListOf<Word<ResponseFingerprint>>()
        for (i in 0 until count) {
            val wordBuilder = WordBuilder<ResponseFingerprint>()
            pre()
            for (symbol in prefix) {
                step(symbol)
            }
            for (symbol in suffix) {
                wordBuilder.append(step(symbol))
            }
            post()
            voteList.add(wordBuilder.toWord())
        }
        return majorityElement(voteList)
    }

    /**
     * Returns the majority element of a list of words.
     *
     * @param words The list of words to determine the majority element from.
     * @return The majority element of the list.
     */
    private fun majorityElement(words: List<Word<ResponseFingerprint>>): Word<ResponseFingerprint> {
        val allPossibilities = HashSet(words)
        val iterator = allPossibilities.iterator()
        var majorityWord = iterator.next()
        var majorityWordOccurrence = words.count { word -> word == majorityWord }
        while (iterator.hasNext()) {
            val word = iterator.next()
            val wordOccurrence = words.count { localWord -> localWord == word }
            if (wordOccurrence > majorityWordOccurrence) {
                majorityWord = word
                majorityWordOccurrence = wordOccurrence
            }
        }
        return majorityWord
    }
}
