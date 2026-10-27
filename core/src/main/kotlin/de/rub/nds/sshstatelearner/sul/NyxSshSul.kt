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
import de.rub.nds.jnyx.NyxProcess
import de.rub.nds.jnyx.NyxReturnValue
import de.rub.nds.sshattacker.core.constants.EncryptionAlgorithm
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshattacker.core.constants.PacketLayerType
import de.rub.nds.sshattacker.core.packet.cipher.PacketGCMCipher
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage
import de.rub.nds.sshattacker.core.protocol.transport.message.VersionExchangeMessage
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshattacker.core.workflow.action.ChangePacketLayerAction
import de.rub.nds.sshattacker.core.workflow.action.ReceiveAction
import de.rub.nds.sshattacker.core.workflow.action.SendAction
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.constants.SulType
import de.rub.nds.sshstatelearner.util.SshConfigManager
import de.rub.nds.tlsattacker.transport.ConnectionEndType
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
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    strictKex: Boolean = DEFAULT_STRICT_KEX_ENABLED,
    disableRekex: Boolean = DEFAULT_DISABLE_REKEX,
    disableEncryptedNewKeys: Boolean = DEFAULT_DISABLE_ENCRYPTED_NEWKEYS,
    unencryptedStageOnly: Boolean = DEFAULT_UNENCRYPTED_STAGE_ONLY,
    limitAuthRequests: Int = DEFAULT_AUTH_REQUEST_LIMIT,
    // Nyx executions are synchronous, so there is no need to wait for responses
    retrieveDelay: Long = 0,
) : NetworkSshSul(name, timeout, resetDelay, stage, kex, strictKex, disableRekex, disableEncryptedNewKeys, unencryptedStageOnly, limitAuthRequests, retrieveDelay) {

    override var connectionAlias = "client"

    private lateinit var nyxOutputStream: RefillableByteArrayInputStream

    private lateinit var nyxInputStream: ByteArrayOutputStream

    private val nyxProcess = NyxProcess.newInstance(sharedir, workdir, cpuId, 32 * 1024, false)

    private var snapshotDecryptorIvCtr: Long = 0

    private var snapshotEncryptorIvCtr: Long = 0

    private var snapshotReadSequenceNumber: Int = 0

    private var snapshotWriteSequenceNumber: Int = 0

    companion object {
        /**
         * Logger for the NyxSshSul class.
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
     * Set up the Nyx-based SSH SUL. On the first call, a new SSH-Attacker state is created and the preamble is
     * executed, after which a snapshot of the target is taken. Subsequent calls restore the state from the snapshot.
     */
    override fun pre() {
        nyxOutputStream = RefillableByteArrayInputStream(ByteArray(0))
        nyxInputStream = ByteArrayOutputStream()
        if (!nyxProcess.isAuxiliarySnapshotPresent) {
            // Snapshot restoration relies on GCM ciphers (see below)
            config = SshConfigManager.getClientConfig(kex, strictKex).apply {
                clientSupportedEncryptionAlgorithmsClientToServer = listOf(EncryptionAlgorithm.AES128_GCM_OPENSSH_COM)
                clientSupportedEncryptionAlgorithmsServerToClient = listOf(EncryptionAlgorithm.AES128_GCM_OPENSSH_COM)
            }
            state = State(config).apply {
                sshContext.transportHandler = NyxTransportHandler(timeout, ConnectionEndType.CLIENT, nyxOutputStream, nyxInputStream)
                sshContext.initTransportHandler()
            }
            connectionClosed = false

            preVersionExchange()
            preamble.forEach {
                executeSymbol(it)
            }
            // TODO: Fix snapshotting in TRANSPORT phase (after version exchange)
            if (!preamble.isEmpty()) {
                nyxProcess.input = byteArrayOf(0x01)
                nyxProcess.exec()
                snapshotReadSequenceNumber = state.sshContext.readSequenceNumber
                snapshotWriteSequenceNumber = state.sshContext.writeSequenceNumber
                snapshotDecryptorIvCtr = (state.sshContext.packetLayer.decryptorCipher as PacketGCMCipher).ivCtr
                snapshotEncryptorIvCtr = (state.sshContext.packetLayer.encryptorCipher as PacketGCMCipher).ivCtr
            }
        } else {
            state.sshContext.apply {
                transportHandler = NyxTransportHandler(timeout, ConnectionEndType.CLIENT, nyxOutputStream, nyxInputStream)
                initTransportHandler()
                readSequenceNumber = snapshotReadSequenceNumber
                writeSequenceNumber = snapshotWriteSequenceNumber
                (packetLayer.decryptor.getPacketCipher(1) as PacketGCMCipher).ivCtr = snapshotDecryptorIvCtr
                (packetLayer.encryptor.getPacketCipher(1) as PacketGCMCipher).ivCtr = snapshotEncryptorIvCtr
            }
            connectionClosed = false
        }
    }

    /**
     * Executes a version exchange on the state and changes the packet layer to binary packets afterward. This function
     * will be called during the pre() lifecycle hook after initializing a new state.
     */
    private fun preVersionExchange() {
        SendAction(connectionAlias, VersionExchangeMessage()).execute(state)
        ReceiveAction(connectionAlias, VersionExchangeMessage()).execute(state)
        ChangePacketLayerAction(connectionAlias, PacketLayerType.BINARY_PACKET).execute(state)
    }

    /**
     * Tear down all stateful components of this SUL and reset the Nyx VM to the snapshot.
     */
    override fun post() {
        // Reset the nyx vm by sending the opcode 0x02 to the agent (will trigger HYPERCALL_KAFL_RELEASE)
        nyxProcess.input = byteArrayOf(0x02)
        nyxProcess.exec()
        super.post()
    }

    /**
     * Sends a single message to the SSH peer by passing the serialized bytes to the Nyx VM and executing it.
     *
     * @param message Message to send.
     */
    override fun sendMessage(message: ProtocolMessage<*>) {
        super.sendMessage(message)
        try {
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
                    LOGGER.error("Nyx execution aborted.")
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

    override val sulType: SulType
        get() = SulType.SERVER

    /**
     * Indicates whether this SUL can be forked for parallel queries.
     */
    override fun canFork(): Boolean = false

    /**
     * Shuts down the Nyx VM and closes the connection.
     */
    override fun close() {
        nyxProcess.close()
        super.close()
    }

    override fun toString(): String {
        return "NyxSshSul[sharedir=$sharedir,workdir=$workdir,cpuId=$cpuId,timeout=$timeout,resetDelay=$resetDelay,connectionClosed=$connectionClosed,executedSteps=$executedSteps]"
    }
}
