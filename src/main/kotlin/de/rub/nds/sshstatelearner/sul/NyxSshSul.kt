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
import de.rub.nds.jnyx.NyxProcess
import de.rub.nds.jnyx.NyxReturnValue
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.PacketLayerType
import de.rub.nds.sshattacker.core.exceptions.AdjustmentException
import de.rub.nds.sshattacker.core.packet.cipher.PacketGCMCipher
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.executor.SendMessageHelper
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseExtractor
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.ConnectionEndType
import de.rub.nds.tlsattacker.transport.socket.SocketState
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.ByteArrayOutputStream
import java.io.IOException
import kotlin.system.exitProcess

class NyxSshSul(
    name: String,
    val sharedir: String,
    val workdir: String = DEFAULT_NYX_WORKDIR,
    val cpuId: Int = DEFAULT_NYX_CPUID,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM
) : SshSul(name, timeout, resetDelay, stage, kex), AutoCloseable {

    private lateinit var nyxOutputStream: RefillableByteArrayInputStream

    private lateinit var nyxInputStream: ByteArrayOutputStream

    private val nyxProcess = NyxProcess.newInstance(sharedir, workdir, cpuId, 32 * 1024, false)

    private var decryptorIvCtr: Long = 0;

    private var encryptorIvCtr: Long = 0;

    /**
     * Indicates whether the underlying network connection is available or closed.
     */
    private var connectionClosed = false

    companion object {
        /**
         * Logger for the NetworkSshSul class.
         */
        private val LOGGER: Logger = LogManager.getLogger()

        /**
         * The default location of the nyx workdir.
         */
        const val DEFAULT_NYX_WORKDIR: String = "/tmp/nyx"

        /**
         * The default CPU id which executes the Nyx VM.
         */
        const val DEFAULT_NYX_CPUID: Int = 0
    }

    /**
     * Set up the network-based SSH SUL by instantiating a new SSH-Attacker state and connection to the peer.
     */
    override fun pre() {
        super.pre()
        nyxOutputStream = RefillableByteArrayInputStream(ByteArray(0))
        nyxInputStream = ByteArrayOutputStream()
        if (!nyxProcess.isAuxiliarySnapshotPresent) {
            state = State(config).apply {
                sshContext.transportHandler = NyxTransportHandler(timeout, ConnectionEndType.CLIENT,  nyxOutputStream, nyxInputStream)
                sshContext.initTransportHandler()
            }

            preVersionExchange()
            preamble.forEach {
                executeSymbol(it)
            }
            nyxProcess.input = byteArrayOf(0x01)
            nyxProcess.exec()
            decryptorIvCtr = (state.sshContext.packetLayer.decryptor.getPacketCipher(1) as PacketGCMCipher).ivCtrDecryption
            encryptorIvCtr = (state.sshContext.packetLayer.encryptor.getPacketCipher(1) as PacketGCMCipher).ivCtrEncryption
        } else {
            // TODO: Make this work for every phase, not just AUTHENTICATION
            state.apply {
                sshContext.transportHandler = NyxTransportHandler(timeout, ConnectionEndType.CLIENT, nyxOutputStream, nyxInputStream)
                sshContext.initTransportHandler()
                sshContext.readSequenceNumber = 4
                sshContext.writeSequenceNumber = 4
                (sshContext.packetLayer.decryptor.getPacketCipher(1) as PacketGCMCipher).ivCtrDecryption = decryptorIvCtr
                (sshContext.packetLayer.encryptor.getPacketCipher(1) as PacketGCMCipher).ivCtrEncryption = encryptorIvCtr
            }
                    }
        connectionClosed = false
    }

    /**
     * Executes a version exchange on the state and changes the packet layer to binary packets afterwards. This function
     * will be called during the pre() lifecycle hook after initializing a new state and opening the connection.
     */
    private fun preVersionExchange() {
        val versionExchange = VersionExchangeMessage()
        versionExchange.getHandler(state.sshContext).preparator.prepare()
        sendMessage(versionExchange)
        ReceiveAction("client", listOf(VersionExchangeMessage())).execute(state)
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
        LOGGER.info("--------------- POST ---------------")
        super.post()
        try {
            // Reset the nyx vm by sending the opcode 0x02 to the agent (will trigger HYPERCALL_KAFL_RELEASE)
            nyxProcess.input = byteArrayOf(0x02)
            nyxProcess.exec()
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
     * Executes a single symbol. Assumes that the config and state have been initialized properly.
     *
     * @param symbol The symbol to execute
     */
    private fun executeSymbol(symbol: SshSymbol): ResponseFingerprint {
        LOGGER.info("Executing symbol: $symbol")
        symbol.message.getHandler(state.sshContext).preparator.prepare()
        sendMessage(symbol.message)
        return retrieveMessages()
    }

    /**
     * A simple wrapper to send a single message to the SSH peer.
     *
     * @param message Message to send.
     */
    private fun sendMessage(message: ProtocolMessage<*>) {
        try {
            SendMessageHelper().sendMessage(state.sshContext, message)
            // The opcode 0x00 indicates a simple input to the agent (no additional hypercalls are being invoked)
            nyxProcess.input = byteArrayOf(0x00) + nyxInputStream.toByteArray()
            nyxInputStream.reset()
            when (nyxProcess.exec()) {
                NyxReturnValue.NORMAL ->
                    LOGGER.info("Nyx execution returned successfully, retrieving a total of ${nyxProcess.output.size} bytes from the output.")
                NyxReturnValue.SOCKET_CLOSED -> {
                    LOGGER.info("Nyx indicated that the underlying socket has been closed by the target. Closing the transport handler.")
                    state.sshContext.transportHandler.closeConnection()
                    connectionClosed = true
                }
                NyxReturnValue.TIMEOUT ->
                    LOGGER.warn("Nyx execution timed out, consider increasing the timeout or check your setup. Continuing anyway - results may not be as expected!")
                NyxReturnValue.ASAN -> {
                    LOGGER.fatal("Nyx execution triggered ASAN handler indicating a memory access violation!")
                    close()
                    exitProcess(1)
                }
                NyxReturnValue.ABORT -> {
                    LOGGER.warn("Nyx execution aborted. Continuing anyway - results may not be as expected!")
                    close()
                    exitProcess(1)
                }
                NyxReturnValue.CRASH -> {
                    LOGGER.error("Nyx execution crashed before returning control to host.")
                    close()
                    exitProcess(1)
                }
                NyxReturnValue.ERROR -> {
                    LOGGER.error("Nyx execution returned with an unspecified error.")
                    close()
                    exitProcess(1)
                }
                NyxReturnValue.IO_ERROR -> {
                    LOGGER.error("Nyx execution returned with an IO error. Make sure your workdir is writeable and Nyx is able to access the necessary files.")
                    close()
                    exitProcess(1)
                }
                NyxReturnValue.INVALID_WRITE_TO_PAYLOAD -> {
                    LOGGER.error("Nyx execution returned with an INVALID_WRITE_TO_PAYLOAD exit code although payload was not read only?!")
                    close()
                    exitProcess(1)
                }
                null -> {
                    LOGGER.error("Nyx execution returned null exit code, this may be a bug with JNyx")
                    exitProcess(1)
                }
            }
            nyxOutputStream.refill(nyxProcess.output)
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
            val action = ReceiveAction("client", listOf())
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
        throw UnsupportedOperationException()
    }

    override fun close() {
        nyxProcess.close()
        state.sshContext.transportHandler.closeConnection()
    }

    override fun toString(): String {
        return "NyxSshSul[sharedir=$sharedir,workdir=$workdir,cpuId=$cpuId,timeout=$timeout,resetDelay=$resetDelay,connectionClosed=$connectionClosed,executedSteps=$executedSteps]"
    }
}
