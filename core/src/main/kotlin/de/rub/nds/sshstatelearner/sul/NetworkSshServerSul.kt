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
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.PacketLayerType
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.SendAction
import de.rub.nds.sshstatelearner.constants.SULTyp
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.util.SshConfigManager
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

class NetworkSshServerSul(
    name: String,
    private val hostname: String,
    private val port: Int,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    strictKex: Boolean = DEFAULT_STRICT_KEX_ENABLED
) : NetworkSshSul(name, timeout, resetDelay, stage, kex, strictKex) {

    override var connectionAlias = "client"

    companion object {
        /**
         * Logger for the NetworkSshSul class.
         */
        private val LOGGER: Logger = LogManager.getLogger()
    }

    /**
     * Set up the network-based SSH for Servers under Test by instantiating a new SSH-Attacker state and connection to the peer.
     */
    override fun pre() {
        config = SshConfigManager.getClientConfig(kex, strictKex)
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
        SendAction(connectionAlias, VersionExchangeMessage()).execute(state)
        ReceiveAction(connectionAlias, VersionExchangeMessage()).execute(state)
        ChangePacketLayerAction(connectionAlias, PacketLayerType.BINARY_PACKET).execute(state)
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
        Thread.sleep(50L)
        return retrieveMessages()
    }

    override val isClient: Boolean
        get() = SULTyp.SERVER_IS_UNDER_TEST.isClient

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
        return NetworkSshServerSul(name, hostname, port, timeout, resetDelay, stage, kex, strictKex)
    }

    override fun toString(): String {
        return "NetworkSshSul[hostname=$hostname,port=$port,timeout=$timeout,resetDelay=$resetDelay,connectionClosed=$connectionClosed,executedSteps=$executedSteps]"
    }
}
