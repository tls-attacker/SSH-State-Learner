/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.learnlib.exception.SULException
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException
import de.rub.nds.sshattacker.core.exceptions.CryptoException
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.executor.SendMessageHelper
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseExtractor
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.IOException

abstract class NetworkSshSul(
    name: String,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    strictKex: Boolean = DEFAULT_STRICT_KEX_ENABLED,
    val disableRekex: Boolean = DEFAULT_DISABLE_REKEX,
    val disableEncryptedNewKeys: Boolean = DEFAULT_DISABLE_ENCRYPTED_NEWKEYS,
    val unencryptedStageOnly: Boolean = DEFAULT_UNENCRYPTED_STAGE_ONLY,
    limitAuthRequests: Int = -1,
    val retrieveDelay: Long = DEFAULT_RETRIEVE_DELAY
) : SshSul(name, timeout, resetDelay, stage, kex, strictKex, limitAuthRequests) {

    /**
     * Indicates whether the underlying network connection is available or closed.
     */
    protected var connectionClosed = false
        protected set

    /**
     * The alias of the connection to use for the transport handler.
     */
    protected abstract var connectionAlias: String

    companion object {
        /**
         * Logger for the NetworkSshSul class.
         */
        private val LOGGER: Logger = LogManager.getLogger()

        /**
         * The default amount of time to wait before retrieving the next response from the SUL in milliseconds.
         */
        const val DEFAULT_RETRIEVE_DELAY: Long = 100
    }

    /**
     * Step the SUL by executing a single symbol.
     */
    override fun step(p0: SshSymbol?): ResponseFingerprint {
        try {
            if (p0 === null) {
                throw SULException(IllegalArgumentException("The provided input SshWord is null"))
            }
            // If the connection is closed, we do not expect any response from the server and therefore can respond without execution
            if (connectionClosed) {
                return ResponseFingerprint(emptyList(), SocketState.CLOSED, false)
            }
            if (((p0 == SshSymbol.MSG_KEXINIT && disableRekex)
                        || (p0 == SshSymbol.MSG_NEWKEYS && disableEncryptedNewKeys)
                        || unencryptedStageOnly) &&
                executedSteps.contains(SshSymbol.MSG_NEWKEYS)) {
                // The learner is trying to rekex (i.e. send a KEXINIT message inside the secure channel) or send an encrypted NEWKEYS message
                // However, the SUL is not allowed to do so. Close the connection to the SUL and return a closed socket state
                state.sshContext.transportHandler.closeConnection()
                connectionClosed = true
                return ResponseFingerprint(emptyList(), SocketState.CLOSED, false)
            }
            // Sometimes limiting the number of authentication requests is necessary to allow the learner to terminate
            if (limitAuthRequests >= 0 &&
                p0.name.startsWith("MSG_USERAUTH_REQUEST") &&
                executedSteps.count { it.name.startsWith("MSG_USERAUTH_REQUEST") } >= limitAuthRequests) {
                // The SUL has reached the limit of authentication requests, but the learner is still trying to send more
                // Close the connection to the SUL and return a closed socket state
                state.sshContext.transportHandler.closeConnection()
                connectionClosed = true
                return ResponseFingerprint(emptyList(), SocketState.CLOSED, false)
            }
            val response = executeSymbol(p0)
            executedSteps.add(p0)

            if (response.socketState == SocketState.SOCKET_EXCEPTION || response.socketState == SocketState.CLOSED) {
                /*
                 * Optimization for handling closed connection: If the response indicates a closed connection (either
                 * by an RST or FIN), we close the transport handler and respond all further steps with a SocketState.CLOSED
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
                LOGGER.error("The responses' socket state indicates more data is available, increase delay between send and receive to avoid incomplete responses")
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
     * Executes a single symbol. Assumes that the config and state have been initialized properly.
     *
     * @param symbol The symbol to execute
     */
    fun executeSymbol(symbol: SshSymbol): ResponseFingerprint {
        LOGGER.trace("Executing symbol: {}", symbol)
        val protocolMessage = symbol.messageConstructor(state.sshContext)
        protocolMessage.getHandler(state.sshContext).preparator.prepare()
        sendMessage(protocolMessage)
        return retrieveMessages(retrieveDelay)
    }

    /**
     * Tear down all stateful components of this SUL, like the internal sulState and transport handler connection.
     */
    override fun post() {
        super.post()
        try {
            state.sshContext.transportHandler.closeConnection()
            connectionClosed = true
            Thread.sleep(resetDelay)
        } catch (e: IOException) {
            LOGGER.error("Unable to close transport handler connection during post() call", e)
        } catch (e: InterruptedException) {
            LOGGER.error("Unable to sleep thread after closing connection", e)
        }
    }

    /**
     * Closes the connection
     */
    override fun close() {
        try {
            state.sshContext.transportHandler.closeConnection()
        } catch (_: Exception) {
            /* Ignore */
        }
    }

    /**
     * A simple wrapper to send a single message to the SSH peer.
     *
     * @param message Message to send.
     */
    protected fun sendMessage(message: ProtocolMessage<*>) {
        try {
            SendMessageHelper.sendMessage(state.sshContext, message)
        } catch (e: IOException) {
            throw SULException(e)
        }
    }

    /**
     * A simple wrapper to retrieve messages from the SSH peer.
     *
     * @return The response fingerprint returned by the SSH peer.
     */
    protected fun retrieveMessages(retrieveDelay: Long = 0): ResponseFingerprint {
        Thread.sleep(retrieveDelay)
        try {
            if (state.sshContext.transportHandler.isClosed) {
                return ResponseFingerprint(listOf(), SocketState.CLOSED, false)
            }
        } catch (e: IOException) {
            throw SULException(e)
        }
        try {
            val action = ReceiveAction(connectionAlias)
            try {
                action.execute(state)
            } catch (_: AdjustmentException) {
            }
            return ResponseExtractor.getFingerprint(state, action)
        } catch (e: IOException) {
            throw SULException(e)
        } catch (e: RuntimeException) {
            if (e.cause is CryptoException) {
                return ResponseFingerprint(listOf(), SocketState.CLOSED, true)
            }
            throw SULException(e)
        }
    }

}
