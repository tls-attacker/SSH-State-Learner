package de.rub.nds.sshstatelearner.sul

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking

class NetworkSshClientSulManager(
    numberOfClientSul: Int,
    startPort: Int,
    name: String,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM
) : SshSul(name, timeout, resetDelay, stage, kex) {

    private val networkSshClientSuls: List<NetworkSshClientSul>
    private var networkSshClientSulsIterator: Iterator<NetworkSshClientSul>
    private var networkSshClientSulToJob: MutableMap<NetworkSshClientSul, Deferred<Unit>> = mutableMapOf()
    private var currentUsedNetworkSshClientSul: NetworkSshClientSul

    init {
        val mutableNetworkSshClientSuls: MutableList<NetworkSshClientSul> = mutableListOf()
        for (i in 1..numberOfClientSul) {
            val networkSshClientSul = NetworkSshClientSul(name, startPort + i, timeout, resetDelay, stage, kex)
            networkSshClientSul.pre()
            mutableNetworkSshClientSuls.add(networkSshClientSul)
        }
        networkSshClientSuls = mutableNetworkSshClientSuls.toList()
        networkSshClientSulsIterator = networkSshClientSuls.iterator()
        currentUsedNetworkSshClientSul = getNextNetworkSshClientSul()
    }

    private fun getNextNetworkSshClientSul(): NetworkSshClientSul {
        return if (networkSshClientSulsIterator.hasNext()) {
            networkSshClientSulsIterator.next()
        } else {
            networkSshClientSulsIterator = networkSshClientSuls.iterator()
            getNextNetworkSshClientSul()
        }
    }


    override fun pre() {
        currentUsedNetworkSshClientSul = getNextNetworkSshClientSul()
        runBlocking {
            networkSshClientSulToJob[currentUsedNetworkSshClientSul]?.join()
        }
    }

    @OptIn(DelicateCoroutinesApi::class)
    fun somethingUsefulOneAsync(networkSshClientSul: NetworkSshClientSul) = GlobalScope.async {
        networkSshClientSul.post()
        networkSshClientSul.pre()
    }

    override fun post() {
        val postJob = somethingUsefulOneAsync(currentUsedNetworkSshClientSul)
        networkSshClientSulToJob[currentUsedNetworkSshClientSul] = postJob
    }

    override fun step(`in`: SshSymbol?): ResponseFingerprint = currentUsedNetworkSshClientSul.step(`in`)


}