package de.rub.nds.sshstatelearner.sul

import de.learnlib.sul.SUL
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.constants.SulType
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

/**
 * This class represents a pooled network SSH client SUL. It is used to pool network SSH client SULs and to provide a
 * SUL that can be used in the learning process.
 */
class PooledNetworkSshClientSul(
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

    override val sulType: SulType
        get() = SulType.CLIENT


    override fun post() {
        sshClientWorker.getSulWasUsed(currentUsedNetworkSshClientSul)
    }

    override fun step(`in`: SshSymbol?): ResponseFingerprint {
        return currentUsedNetworkSshClientSul.step(`in`)
    }

    override fun canFork(): Boolean = true


    override fun fork(): SUL<SshSymbol, ResponseFingerprint> =
        PooledNetworkSshClientSul(name, timeout, resetDelay, stage, kex, sshClientWorker)

}