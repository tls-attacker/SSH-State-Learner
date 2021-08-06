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
import de.rub.nds.sshattacker.core.state.State
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol
import de.rub.nds.tlsattacker.transport.socket.SocketState
import de.rub.nds.tlsattacker.transport.tcp.ClientTcpTransportHandler
import java.io.IOException
import java.lang.IllegalArgumentException
import java.lang.RuntimeException
import org.apache.logging.log4j.LogManager

class SshSul : SUL<SshSymbol, ResponseFingerprint> {

    companion object {
        private val LOGGER = LogManager.getLogger()
    }

    /**
     * The config of the SSH-Attacker
     */
    private lateinit var config: Config

    /**
     * The state of the SSH-Attacker
     */
    private lateinit var state: State

    /**
     * Indicates whether the underlying sockets are available or closed
     */
    private var closed = false

    /**
     * A list of all executed steps on the current SSH connection
     */
    private val executedSteps = mutableListOf<SshSymbol>()

    /**
     * Set up the SSH SUL by instantiating a new SSH-Attacker state and connecting to the peer
     */
    override fun pre() {
        config = Config.createConfig().apply {
            stopActionsAfterDisconnect = false
            stopActionsAfterIOException = false
        }
        state = State(config).apply {
            sshContext.transportHandler = ClientTcpTransportHandler(ArgsSul.timeout, ArgsSul.timeout, ArgsSul.hostname, ArgsSul.port)
            sshContext.initTransportHandler()
        }
        closed = false
    }

    /**
     * Tear down all stateful components of this SUL, like the internal sulState and transport handler connection
     */
    override fun post() {
        try {
            state.sshContext.transportHandler.closeConnection()
            Thread.sleep(ArgsSul.resetDelay)
        } catch (e: IOException) {
            LOGGER.error("Unable to close transport handler connection during post() call", e)
        } catch (e: InterruptedException) {
            LOGGER.error("Unable to sleep thread after closing connection", e)
        }
        executedSteps.clear()
    }

    /**
     * Step the SUL by executing a single SshWord
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
            if (closed) {
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
                closed = true
            } else if (response.socketState == SocketState.DATA_AVAILABLE) {
                /*
                 * If the socketState is SocketState.DATA_AVAILABLE, more data is available to read. As a consequence,
                 * the response fingerprint does not contain all response messages from the server.
                 * This can lead to the algorithm not terminating due to different behaviours on the same words. It must
                 * be avoided by all costs (i.e. increase delay between send and receive actions)
                 */
                LOGGER.warn("The responses' socket state indicates more data is available, increase delay between send and receive to avoid incomplete responses")
            }
            return response
        } catch (e: IOException) {
            state.sshContext.transportHandler.closeConnection()
            closed = true
            LOGGER.error("Caught an IOException while stepping the SUL with the following SshWord: $p0", e)
            throw SULException(e)
        }
    }

    /**
     * Indicates whether this SUL can be forked for parallel queries
     */
    override fun canFork(): Boolean {
        return true
    }

    /**
     * Returns a new SUL instance that must behave exactly as the original SUL
     */
    override fun fork(): SUL<SshSymbol, ResponseFingerprint> {
        return SshSul()
    }

    override fun toString(): String {
        return "SshSul[executedSteps=$executedSteps]"
    }
}
