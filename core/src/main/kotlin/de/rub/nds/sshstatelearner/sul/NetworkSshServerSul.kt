/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.sul

import de.rub.nds.protocol.exception.TransportHandlerConnectException
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.PacketLayerType
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.SendAction
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.constants.SulType
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
    strictKex: Boolean = DEFAULT_STRICT_KEX_ENABLED,
    disableRekex: Boolean = DEFAULT_DISABLE_REKEX,
    disableEncryptedNewKeys: Boolean = DEFAULT_DISABLE_ENCRYPTED_NEWKEYS,
    unencryptedStageOnly: Boolean = DEFAULT_UNENCRYPTED_STAGE_ONLY,
    limitAuthRequests: Int = DEFAULT_AUTH_REQUEST_LIMIT,
    retrieveDelay: Long = DEFAULT_RETRIEVE_DELAY,
) : NetworkSshSul(name, timeout, resetDelay, stage, kex, strictKex, disableRekex, disableEncryptedNewKeys, unencryptedStageOnly, limitAuthRequests, retrieveDelay) {

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
        var connectionSuccessful: Boolean
        do {
            try {
                state = State(config).apply {
                    sshContext.transportHandler = ClientTcpTransportHandler(timeout, timeout, hostname, port)
                    sshContext.initTransportHandler()
                }
                connectionSuccessful = true
            } catch (e: TransportHandlerConnectException) {
                LOGGER.error("Could not connect to the server at $hostname:$port.")
                connectionSuccessful = false
            } catch (e: Exception) {
                LOGGER.error("An error occurred while connecting to the server: ${e.message}")
                connectionSuccessful = false
            }
        } while (!connectionSuccessful)
        connectionClosed = false

        preVersionExchange()
        // TODO: Exception handling for preamble
        preamble.forEach {
            executeSymbol(it)
        }
    }

    /**
     * Executes a version exchange on the state and changes the packet layer to binary packets afterward. This function
     * will be called during the pre() lifecycle hook after initializing a new state and opening the connection.
     */
    private fun preVersionExchange() {
        SendAction(connectionAlias, VersionExchangeMessage()).execute(state)
        ReceiveAction(connectionAlias, VersionExchangeMessage()).execute(state)
        ChangePacketLayerAction(connectionAlias, PacketLayerType.BINARY_PACKET).execute(state)
    }

    override val sulType: SulType
        get() = SulType.SERVER

    /**
     * Indicates whether this SUL can be forked for parallel queries.
     */
    override fun canFork(): Boolean = false

    override fun toString(): String {
        return "NetworkSshServerSul[hostname=$hostname,port=$port,timeout=$timeout,resetDelay=$resetDelay,retrieveDelay=$retrieveDelay,connectionClosed=$connectionClosed,executedSteps=$executedSteps]"
    }
}
