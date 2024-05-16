package de.rub.nds.sshstatelearner.sul

import de.learnlib.api.SUL
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class NetworkSshClientSulProxy(
    name: String,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    private val androidSshClientWorker: AndroidSshClientWorker
) : SshSul(name, timeout, resetDelay, stage, kex) {
    private lateinit var currentUsedNetworkSshClientSul: NetworkSshClientSul

    override fun pre() {
        currentUsedNetworkSshClientSul = androidSshClientWorker.getReadySulToUse()
    }


    override fun post() {
        androidSshClientWorker.getSulWasUsed(currentUsedNetworkSshClientSul)
    }

    override fun step(`in`: SshSymbol?): ResponseFingerprint {
        return currentUsedNetworkSshClientSul.step(`in`)
    }

    override fun canFork(): Boolean = true


    override fun fork(): SUL<SshSymbol, ResponseFingerprint> =
        NetworkSshClientSulProxy(name, timeout, resetDelay, stage, kex, androidSshClientWorker)

}