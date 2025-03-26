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
import de.rub.nds.sshattacker.core.constants.ConnectionDirection
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.PacketLayerType
import de.rub.nds.sshattacker.core.exceptions.TransportHandlerConnectException
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.SendAction
import de.rub.nds.sshstatelearner.constants.SULTyp
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.util.SshConfigManager
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import kotlin.time.DurationUnit
import kotlin.time.toDuration

class NetworkSshClientSul(
    name: String,
    val port: Int,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    strictKex: Boolean = DEFAULT_STRICT_KEX_ENABLED,
    private val enableEncryptionOnNewKeysMessage: ConnectionDirection = ConnectionDirection.BOTH,
    private val clientConnectionHandler: ClientConnectionHandler = EmptyClientConnectionHandler(),
) : NetworkSshSul(name, timeout, resetDelay, stage, kex, strictKex) {

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
        config = SshConfigManager.getServerConfig(kex, strictKex)
        // Initialize transport handler
        var serverIsReady = false
        var connectionIsReady = false
        // In case something goes wrong: while
        while (!serverIsReady || !connectionIsReady) {
            config.enableEncryptionOnNewKeysMessage = enableEncryptionOnNewKeysMessage
            state = State(config)

            try {
                runBlocking {
                    // Starts a timer in case something goes wrong to terminate the other jobs.
                    // If everything goes smoothly, the timer will be stopped.
                    val jobSomethingWentWrongTimer =
                        launch(Dispatchers.IO) {
                            delay(10.toDuration(DurationUnit.SECONDS))
                            state.sshContext.transportHandler.closeConnection()
                            LOGGER.warn("SUL with port ${port} could not be started successfully within 60 seconds! Try again!")
                            this.cancel()
                        }

                    val jobServer = launch(Dispatchers.IO) {
                        state.sshContext.transportHandler = ServerTcpTransportHandler(timeout, timeout, port)
                        state.sshContext.initTransportHandler()
                        connectionClosed = false
                        serverIsReady = true
                    }
                    val jobClient = launch(Dispatchers.IO) {
                        clientConnectionHandler.subscribeForConnection()
                        connectionIsReady = true
                    }
                    joinAll(jobClient, jobServer)
                    jobSomethingWentWrongTimer.cancel()

                    // The case where the PreVersionExchange fails
                    if (!preVersionExchange()) {
                        state.sshContext.transportHandler.closeConnection()
                        serverIsReady = false
                        connectionIsReady = false
                    } else {
                        // TODO: Exception handling for preamble
                        preamble.forEach {
                            executeSymbol(it)
                        }
                    }
                }
            } catch (e: TransportHandlerConnectException) {
                LOGGER.warn(e.message)
            }
        }
    }

    /**
     * Executes a version exchange on the state and changes the packet layer to binary packets afterwards. This function
     * will be called during the pre() lifecycle hook after initializing a new state and opening the connection.
     */
    private fun preVersionExchange(): Boolean {
        val receiveMessageVersionExchange =
            ReceiveAction(connectionAlias, SshSymbol.MSG_VERSION_EXCHANGE.messageConstructor(state.sshContext)).apply { execute(state) }
        SendAction(connectionAlias, SshSymbol.MSG_VERSION_EXCHANGE.messageConstructor(state.sshContext)).execute(state)
        ChangePacketLayerAction(connectionAlias, PacketLayerType.BINARY_PACKET).execute(state)
        Thread.sleep(timeout)
        val receiveKexInit =
            ReceiveAction(connectionAlias, SshSymbol.MSG_KEXINIT.messageConstructor(state.sshContext)).apply { execute(state) }
        // Checks if everything went according to plan and if the connection is still open
        return receiveMessageVersionExchange.executedAsPlanned() && receiveKexInit.executedAsPlanned() && !state.sshContext.transportHandler.isClosed
    }

    /**
     * Executes a single symbol. Assumes that the config and state have been initialized properly.
     *
     * @param symbol The symbol to execute
     */
    override fun executeSymbol(symbol: SshSymbol): ResponseFingerprint {
        LOGGER.trace("Executing symbol: {}", symbol)
        val protocolMessage = symbol.messageConstructor(state.sshContext)
        protocolMessage.getHandler(state.sshContext).getPreparator().prepare()
        sendMessage(protocolMessage)
        // TODO: Find a better way to allow for custom retrieve delays without shifting implementation to symbols
        val retrieveDelay = 50L
        return retrieveMessages(retrieveDelay)
    }

    override val isClient: Boolean
        get() = SULTyp.CLIENT_IS_UNDER_TEST.isClient

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
        return NetworkSshClientSul(
            name,
            port,
            timeout,
            resetDelay,
            stage,
            kex,
            strictKex,
            enableEncryptionOnNewKeysMessage,
            clientConnectionHandler
        )
    }

    override fun toString(): String {
        return "NetworkSshClientSul[port=$port,timeout=$timeout,resetDelay=$resetDelay,connectionClosed=$connectionClosed,executedSteps=$executedSteps]"
    }
}
