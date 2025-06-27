/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.learnlib.sul.SUL
import de.rub.nds.sshattacker.core.config.Config
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.constants.SulType
import de.rub.nds.sshstatelearner.extraction.HappyFlowFactory
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.word.Word
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

abstract class SshSul(
    val name: String,
    val timeout: Long = DEFAULT_SUL_TIMEOUT,
    val resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    val stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    val kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    val strictKex: Boolean = DEFAULT_STRICT_KEX_ENABLED,
    val limitAuthRequests: Int = -1
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
    abstract val sulType: SulType

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

        /**
         * The default value for whether to disable key re-exchange (i.e. sending SSH_MSG_KEXINIT in the secure channel)
         */
        const val DEFAULT_DISABLE_REKEX = false

        /**
         * The default value for whether to disable encrypted new keys (i.e. sending SSH_MSG_NEWKEYS in the secure channel)
         */
        const val DEFAULT_DISABLE_ENCRYPTED_NEWKEYS = false

        /**
         * The default value for whether to close the connection after sending an encrypted SERVICE_REQUEST message.
         */
        const val DEFAULT_UNENCRYPTED_STAGE_ONLY = false

        /**
         * The default value for the maximum number of authentication requests to be sent before closing the connection.
         * Set to -1 to disable this feature.
         */
        const val DEFAULT_AUTH_REQUEST_LIMIT = -1
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
                    sulType,
                    ProtocolStage.TRANSPORT,
                    kex
                )
            )
        }
        if (stage == ProtocolStage.CONNECTION) {
            preamble = preamble.concat(
                HappyFlowFactory.constructHappyFlow(
                    sulType,
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
}
