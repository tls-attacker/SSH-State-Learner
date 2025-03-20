package de.rub.nds.sshstatelearner.sul

import de.learnlib.sul.SUL
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.constants.SULTyp
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

/**
 * SUL Proxy die sich einen SUL aus dem Pool holt.
 */
class NetworkSshClientSulProxy(
    name: String,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    private val sshClientWorker: SshClientWorker
) : SshSul(name, timeout, resetDelay, stage, kex) {
    private lateinit var currentUsedNetworkSshClientSul: NetworkSshClientSul

    override fun pre() {
        currentUsedNetworkSshClientSul = sshClientWorker.getReadySulToUse()
    }

    override val isClient: Boolean
        get() = SULTyp.CLIENT_IS_UNDER_TEST.isClient


    override fun post() {
        sshClientWorker.getSulWasUsed(currentUsedNetworkSshClientSul)
    }

    override fun step(`in`: SshSymbol?): ResponseFingerprint {
        return currentUsedNetworkSshClientSul.step(`in`)
    }

    override fun canFork(): Boolean = true


    override fun fork(): SUL<SshSymbol, ResponseFingerprint> =
        NetworkSshClientSulProxy(name, timeout, resetDelay, stage, kex, sshClientWorker)

}