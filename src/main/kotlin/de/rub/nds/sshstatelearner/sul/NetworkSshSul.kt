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
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.PacketLayerType
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.SendAction
import de.rub.nds.sshattacker.core.workflow.action.executor.SendMessageHelper
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseExtractor
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.IOException
import java.lang.IllegalArgumentException

class NetworkSshSul(
    name: String,
    val hostname: String,
    val port: Int,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM
) : SshSul(name, timeout, resetDelay, stage, kex) {

    /**
     * Indicates whether the underlying network connection is available or closed.
     */
    private var connectionClosed = false

    companion object {
        /**
         * Logger for the NetworkSshSul class.
         */
        private val LOGGER: Logger = LogManager.getLogger()
    }

    /**
     * Set up the network-based SSH SUL by instantiating a new SSH-Attacker state and connection to the peer.
     */
    override fun pre() {
        super.pre()
        // Initialize transport handler
        state = State(config).apply {
            sshContext.transportHandler = ClientTcpTransportHandler(timeout, timeout, hostname, port)
            sshContext.initTransportHandler()
        }
        connectionClosed = false

        preVersionExchange()
        // TODO: Exception handling for preamble
        preamble.forEach {
            executeSymbol(it)
        }
    }

    /**
     * Executes a version exchange on the state and changes the packet layer to binary packets afterwards. This function
     * will be called during the pre() lifecycle hook after initializing a new state and opening the connection.
     */
    private fun preVersionExchange() {
        SendAction("client", VersionExchangeMessage()).execute(state)
        ReceiveAction("client", VersionExchangeMessage()).execute(state)
        ChangePacketLayerAction("client", PacketLayerType.BINARY_PACKET).execute(state)
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
                return ResponseFingerprint(emptyList(), SocketState.CLOSED)
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

    override fun close() {
        try {
            state.sshContext.transportHandler.closeConnection()
        } catch (_: Exception) { /* Ignore */ }
    }

    /**
     * Executes a single symbol. Assumes that the config and state have been initialized properly.
     *
     * @param symbol The symbol to execute
     */
    private fun executeSymbol(symbol: SshSymbol): ResponseFingerprint {
        LOGGER.trace("Executing symbol: {}", symbol)
        symbol.message.getHandler(state.sshContext).preparator.prepare()
        // TODO: Find a better way to allow for custom retrieve delays without shifting implementation to symbols
        sendMessage(symbol.message)
        val retrieveDelay = if (symbol == SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_INVALID) 2500L else 50L
        Thread.sleep(retrieveDelay)
        return retrieveMessages()
    }

    /**
     * A simple wrapper to send a single message to the SSH peer.
     *
     * @param message Message to send.
     */
    private fun sendMessage(message: ProtocolMessage<*>) {
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
    private fun retrieveMessages(): ResponseFingerprint {
        try {
            if (state.sshContext.transportHandler.isClosed) {
                return ResponseFingerprint(listOf(), SocketState.CLOSED)
            }
        } catch (e: IOException) {
            throw SULException(e)
        }
        try {
            val action = ReceiveAction("client")
            try {
                action.execute(state)
            } catch (_: AdjustmentException) {
            }
            return ResponseExtractor.getFingerprint(state, action)
        } catch (e: IOException) {
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
        return NetworkSshSul(name, hostname, port, timeout, resetDelay)
    }

    override fun toString(): String {
        return "NetworkSshSul[hostname=$hostname,port=$port,timeout=$timeout,resetDelay=$resetDelay,connectionClosed=$connectionClosed,executedSteps=$executedSteps]"
    }
}
