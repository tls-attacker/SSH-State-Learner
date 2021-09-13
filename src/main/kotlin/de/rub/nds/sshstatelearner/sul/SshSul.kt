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
import de.learnlib.api.exception.SULException
import de.rub.nds.sshattacker.core.config.Config
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.sul.symbols.HappyFlowFactory
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import de.rub.nds.sshstatelearner.util.LoggerCompanion
import de.rub.nds.tlsattacker.transport.socket.SocketState
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler
import net.automatalib.words.Word
import java.io.IOException
import java.lang.IllegalArgumentException
import java.lang.RuntimeException

class SshSul(val hostname: String, val port: Int, val timeout: Long = DEFAULT_TRANSPORT_HANDLER_TIMEOUT, val resetDelay: Long = DEFAULT_SUL_RESET_DELAY, val stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE, val kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM) : SUL<SshSymbol, ResponseFingerprint> {
    /**
     * The config of the SSH-Attacker.
     */
    private lateinit var config: Config

    /**
     * The state of the SSH-Attacker.
     */
    private lateinit var state: State

    /**
     * Indicates whether the underlying network connection is available or closed.
     */
    var connectionClosed = false
        private set

    /**
     * A list of SshSymbols that need to be executed within pre() to reach the defined protocol stage.
     */
    private val preamble: Word<SshSymbol> = constructPreamble()

    /**
     * A list of all executed steps on the current SSH connection.
     */
    private val executedSteps = mutableListOf<SshSymbol>()

    companion object : LoggerCompanion() {
        /**
         * A non-negative integer value indicating the default transport handler timeout.
         */
        const val DEFAULT_TRANSPORT_HANDLER_TIMEOUT: Long = 1000

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
        val DEFAULT_KEX_ALGORITHM: KeyExchangeAlgorithm = KeyExchangeAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256
    }

    /**
     * Constructs a list of SshSymbols that need to be executed to reach the provided SSH protocol stage.
     *
     * @return List of SshSymbols whose execution lead to the provided SSH protocol stage.
     */
    private fun constructPreamble(): Word<SshSymbol> {
        return when(stage) {
            ProtocolStage.TRANSPORT -> Word.epsilon()
            ProtocolStage.AUTHENTICATION -> HappyFlowFactory.constructHappyFlow(ProtocolStage.TRANSPORT, kex)
            ProtocolStage.CONNECTION -> HappyFlowFactory.constructHappyFlow(ProtocolStage.TRANSPORT, kex).concat(
                HappyFlowFactory.constructHappyFlow(ProtocolStage.AUTHENTICATION, kex)
            )
        }
    }

    /**
     * Set up the SSH SUL by instantiating a new SSH-Attacker state and connection to the peer.
     */
    override fun pre() {
        config = Config.createConfig().apply {
            stopActionsAfterDisconnect = false
            stopActionsAfterIOException = false
            avoidAdjustmentExceptions = true
            avoidPreparationExceptions = true
            clientSupportedKeyExchangeAlgorithms = listOf(kex)
            serviceName = "ssh-userauth"
        }
        state = State(config).apply {
            sshContext.transportHandler = ClientTcpTransportHandler(timeout, timeout, hostname, port)
            sshContext.initTransportHandler()
        }
        connectionClosed = false
        // TODO: Exception handling for preamble
        preamble.forEach {
            it.execute(state)
        }
    }

    /**
     * Tear down all stateful components of this SUL, like the internal sulState and transport handler connection.
     */
    override fun post() {
        try {
            state.sshContext.transportHandler.closeConnection()
            connectionClosed = true
            Thread.sleep(resetDelay)
        } catch (e: IOException) {
            LOGGER.error("Unable to close transport handler connection during post() call", e)
        } catch (e: InterruptedException) {
            LOGGER.error("Unable to sleep thread after closing connection", e)
        }
        executedSteps.clear()
    }

    /**
     * Step the SUL by executing a single SshWord.
     */
    override fun step(p0: SshSymbol?): ResponseFingerprint {
        try {
            /*
             * Assuming the SUL is used according to its lifecycle and only non-null words are used, the following two
             * branches should never be executed
             */
            if (!this::state.isInitialized) {
                throw SULException(RuntimeException("SSH-Attacker states are not initialized"))
            } else if (p0 === null) {
                throw SULException(IllegalArgumentException("The provided input SshWord is null"))
            }

            // If the connection is closed, we do not expect any response from the server and therefore can respond without execution
            if (connectionClosed) {
                return ResponseFingerprint(emptyList(), SocketState.CLOSED)
            }

            val response = p0.execute(state)
            executedSteps.add(p0)
            if (response.socketState == SocketState.SOCKET_EXCEPTION || response.socketState == SocketState.CLOSED) {
                /*
                 * Optimization for handling closed connection: If the response indicates a closed connection (either
                 * by a RST or FIN), we close the transport handler and respond all further steps with a SocketState.CLOSED
                 */
                state.sshContext.transportHandler.closeConnection()
                connectionClosed = true
            } else if (response.socketState == SocketState.DATA_AVAILABLE) {
                /*
                 * If the socketState is SocketState.DATA_AVAILABLE, more data is available to read. As a consequence,
                 * the response fingerprint does not contain all response messages from the server.
                 * This can lead to the algorithm not terminating due to different behaviours on the same words. It must
                 * be avoided at all costs (i.e. increase delay between send and receive actions)
                 */
                LOGGER.warn("The responses' socket state indicates more data is available, increase delay between send and receive to avoid incomplete responses")
            }
            return response
        } catch (e: IOException) {
            state.sshContext.transportHandler.closeConnection()
            connectionClosed = true
            LOGGER.error("Caught an IOException while stepping the SUL with the following SshWord: $p0", e)
            throw SULException(e)
        }
    }

    /**
     * Indicates whether this SUL can be forked for parallel queries.
     */
    override fun canFork(): Boolean {
        return true
    }

    /**
     * Returns a new SUL instance that must behave exactly as the original SUL.
     */
    override fun fork(): SUL<SshSymbol, ResponseFingerprint> {
        return SshSul(hostname, port, timeout, resetDelay)
    }

    override fun toString(): String {
        return "SshSul[hostname=$hostname,port=$port,timeout=$timeout,resetDelay=$resetDelay,connectionClosed=$connectionClosed,executedSteps=$executedSteps]"
    }
}
