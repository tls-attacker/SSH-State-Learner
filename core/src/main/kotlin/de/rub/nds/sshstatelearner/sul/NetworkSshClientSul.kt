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
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.PacketLayerType
import de.rub.nds.sshattacker.core.exceptions.TransportHandlerConnectException
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.SendAction
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.util.SshConfigManager
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

class NetworkSshClientSul(
    name: String,
    private val port: Int,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    private val clientConnectionHandler: ClientConnectionHandler = EmptyClientConnectionHandler(),
) : NetworkSshSul(name, timeout, resetDelay, stage, kex) {

    override var connectionAlias = "server"

    companion object {
        /**
         * Logger for the NetworkSshSul class.
         */
        private val LOGGER: Logger = LogManager.getLogger()
    }

    /**
     * Set up the network-based SSH for Clients under Test by instantiating a new SSH-Attacker state and connection to the peer.
     */
    override fun pre() {
        config = SshConfigManager.getServerConfig(kex)

        // Initialize transport handler
        var serverIsReady = false
        var connectionIsReady = false
        while (!serverIsReady || !connectionIsReady) {
            state = State(config)
            try {
                runBlocking {
                    launch(Dispatchers.IO) {
                        state.sshContext.transportHandler = ServerTcpTransportHandler(timeout, timeout, port)
                        state.sshContext.initTransportHandler()
                        connectionClosed = false
                        serverIsReady = true
                    }
                    launch(Dispatchers.IO) {
                        clientConnectionHandler.subscribeForConnection()
                        connectionIsReady = true
                    }
                }
            } catch (e: TransportHandlerConnectException) {
                LOGGER.warn(e.message)
            }
        }
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
        ReceiveAction(connectionAlias, SshSymbol.MSG_VERSION_EXCHANGE.messageCreator()).execute(state)
        SendAction(connectionAlias, SshSymbol.MSG_VERSION_EXCHANGE.messageCreator()).execute(state)
        ChangePacketLayerAction(connectionAlias, PacketLayerType.BINARY_PACKET).execute(state)
        ReceiveAction(connectionAlias, SshSymbol.MSG_KEXINIT.messageCreator()).execute(state)
    }

    /**
     * Executes a single symbol. Assumes that the config and state have been initialized properly.
     *
     * @param symbol The symbol to execute
     */
    override fun executeSymbol(symbol: SshSymbol): ResponseFingerprint {
        LOGGER.trace("Executing symbol: {}", symbol)
        val protocolMessage = symbol.messageCreator()
        protocolMessage.getHandler(state.sshContext).preparator.prepare()
        // TODO: Find a better way to allow for custom retrieve delays without shifting implementation to symbols
        sendMessage(protocolMessage)
        val retrieveDelay = 50L
        return retrieveMessages(retrieveDelay)
    }

    /**
     * Indicates whether this SUL can be forked for parallel queries.
     */
    override fun canFork(): Boolean {
        return false
    }

    /**
     * Returns a new SUL instance that must behave exactly as the original SUL.
     */
    override fun fork(): SUL<SshSymbol, ResponseFingerprint> {
        return NetworkSshClientSul(name, port, timeout, resetDelay)
    }

    override fun toString(): String {
        return "NetworkSshClientSul[port=$port,timeout=$timeout,resetDelay=$resetDelay,connectionClosed=$connectionClosed,executedSteps=$executedSteps]"
    }
}
