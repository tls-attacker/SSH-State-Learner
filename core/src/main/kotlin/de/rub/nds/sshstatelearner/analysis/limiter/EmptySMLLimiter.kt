package de.rub.nds.sshstatelearner.analysis.limiter

import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.tlsattacker.transport.socket.SocketState

class EmptySMLLimiter : SMLLimiter() {
    override fun init() {
        //Empty
    }

    override fun pre() {
        //Empty
    }

    override fun post() {
        //Empty
    }

    override fun step(
        inputSymbol: SshSymbol?,
        defaultStep: (inputSymbol: SshSymbol?) -> ResponseFingerprint,
        currentSocketState: SocketState
    ): ResponseFingerprint {
        return defaultStep(inputSymbol)
    }
}