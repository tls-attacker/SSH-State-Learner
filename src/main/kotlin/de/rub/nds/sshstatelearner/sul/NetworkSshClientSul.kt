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
import de.rub.nds.modifiablevariable.util.ArrayConverter
import de.rub.nds.sshattacker.core.config.Config
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.NamedEcGroup
import de.rub.nds.sshattacker.core.constants.PacketLayerType
import de.rub.nds.sshattacker.core.constants.PublicKeyAlgorithm
import de.rub.nds.sshattacker.core.constants.PublicKeyFormat
import de.rub.nds.sshattacker.core.constants.RunningModeType
import de.rub.nds.sshattacker.core.crypto.ec.PointFormatter
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPrivateKey
import de.rub.nds.sshattacker.core.crypto.keys.CustomEcPublicKey
import de.rub.nds.sshattacker.core.crypto.keys.SshPublicKey
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.SendAction
import de.rub.nds.sshattacker.core.workflow.action.executor.SendMessageHelper
import de.rub.nds.sshattacker.core.workflow.factory.WorkflowTraceType
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseExtractor
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler
import de.rub.nds.tlsattacker.transport.tcp.ServerTcpTransportHandler
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.IOException
import java.lang.IllegalArgumentException
import java.math.BigInteger

class NetworkSshClientSul(
    name: String,
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

    private fun forOverClassPre() {
        config = Config.createConfig().apply {
            // TODO: Allow state initialization without specifying trace type
            workflowTraceType = WorkflowTraceType.KEX_INIT_ONLY
            stopActionsAfterDisconnect = false
            stopActionsAfterIOException = false
            serverSupportedKeyExchangeAlgorithms = listOf(kex)
            serviceName = "ssh-userauth"
            defaultRunningMode = RunningModeType.SERVER
            // TODO: Fix CTR
            clientSupportedEncryptionAlgorithmsClientToServer = listOf(EncryptionAlgorithm.AES128_GCM_OPENSSH_COM)
            clientSupportedEncryptionAlgorithmsServerToClient = listOf(EncryptionAlgorithm.AES128_GCM_OPENSSH_COM)
            serverSupportedHostKeyAlgorithms = listOf(PublicKeyAlgorithm.ECDSA_SHA2_NISTP521)
            clientSupportedHostKeyAlgorithms = listOf(PublicKeyAlgorithm.ECDSA_SHA2_NISTP521)
            serverSupportedKeyExchangeAlgorithms = listOf(kex)
            hostKeys = listOf(
                SshPublicKey(
                    PublicKeyFormat.ECDSA_SHA2_NISTP521,
                    CustomEcPublicKey(
                        PointFormatter.formatFromByteArray(
                            NamedEcGroup.SECP521R1,
                            ArrayConverter.hexStringToByteArray(
                                "04007a9a61317b93ec991102aea304" +
                                        "7641b3b91254d5267ac1bade8972db" +
                                        "7ee61dd0189d5663ff1988815e2632" +
                                        "7634465f38f12112db2caa87020528" +
                                        "e40091140810da01c643704d3bad15" +
                                        "88572e1eeb36080c25e307e99f5263" +
                                        "6c926c5c15eccaf5526ff2c79e3e5f" +
                                        "683be0bfa5bd806217b690fd6bbfcc" +
                                        "ca27cd82fd79bb194fccae7858"
                            )
                        ),
                        NamedEcGroup.SECP521R1
                    ),
                    CustomEcPrivateKey(
                        BigInteger(
                            "01cac52efb225c5321f43e80bd28ee" +
                                    "e0c9f21297684305586bcc68dded8d" +
                                    "dc2acb2554b015810c8913211a8238" +
                                    "a0cb56aa9c2295143e62afa476b4a4" +
                                    "4fad5fee4717",
                            16
                        ),
                        NamedEcGroup.SECP521R1
                    )
                )
            )
        }
    }

    /**
     * Set up the network-based SSH SUL by instantiating a new SSH-Attacker state and connection to the peer.
     */
    override fun pre() {
        forOverClassPre()
        // Initialize transport handler
        state = State(config).apply {
            sshContext.transportHandler = ServerTcpTransportHandler(timeout, timeout, port)
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

        SendAction("server", VersionExchangeMessage()).execute(state)
        ReceiveAction("server", VersionExchangeMessage()).execute(state)
        ChangePacketLayerAction("server", PacketLayerType.BINARY_PACKET).execute(state)
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
        } catch (_: Exception) { /* Ignore */
        }
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
            val action = ReceiveAction("server")
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
