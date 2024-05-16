package de.rub.nds.sshstatelearner.analysis.limiter

import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState

abstract class SMLLimiter {
    abstract fun init()
    abstract fun pre()
    abstract fun post()

    abstract fun step(
        inputSymbol: SshSymbol?,
        defaultStep: (inputSymbol: SshSymbol?) -> ResponseFingerprint,
        currentSocketState: SocketState
    ): ResponseFingerprint
}