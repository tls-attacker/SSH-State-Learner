package de.rub.nds.sshstatelearner.sul

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking

class NetworkSshClientSulManager(
    name: String,
    timeout: Long = DEFAULT_SUL_TIMEOUT,
    resetDelay: Long = DEFAULT_SUL_RESET_DELAY,
    stage: ProtocolStage = DEFAULT_PROTOCOL_STAGE,
    kex: KeyExchangeAlgorithm = DEFAULT_KEX_ALGORITHM,
    clientConnectionHandlers: List<ClientConnectionHandler>
) : SshSul(name, timeout, resetDelay, stage, kex) {
    private val scope = CoroutineScope(Dispatchers.IO)

    private val networkSshClientSuls: List<NetworkSshClientSul>
    private var networkSshClientSulsIterator: Iterator<NetworkSshClientSul>
    private var networkSshClientSulToJob: MutableMap<NetworkSshClientSul, Deferred<Unit>> = mutableMapOf()
    private var currentUsedNetworkSshClientSul: NetworkSshClientSul

    init {
        val mutableNetworkSshClientSuls: MutableList<NetworkSshClientSul> = mutableListOf()
        for (clientConnectionHandler in clientConnectionHandlers) {
            val networkSshClientSul = NetworkSshClientSul(
                name,
                clientConnectionHandler.getPort(),
                timeout,
                resetDelay,
                stage,
                kex,
                clientConnectionHandler
            )
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
        var preJobIsFinished: Deferred<Unit>?
        do {
            currentUsedNetworkSshClientSul = getNextNetworkSshClientSul()
            preJobIsFinished = networkSshClientSulToJob[currentUsedNetworkSshClientSul]
        } while (preJobIsFinished != null && preJobIsFinished.isActive)
        runBlocking {
            preJobIsFinished?.join()
        }
    }


    fun somethingUsefulOneAsync(networkSshClientSul: NetworkSshClientSul) = scope.async {
        networkSshClientSul.post()
        networkSshClientSul.pre()
    }


    override fun post() {
        val postJob = somethingUsefulOneAsync(currentUsedNetworkSshClientSul)
        networkSshClientSulToJob[currentUsedNetworkSshClientSul] = postJob
    }

    override fun step(`in`: SshSymbol?): ResponseFingerprint = currentUsedNetworkSshClientSul.step(`in`)

    fun cancel(): Unit = scope.cancel()
}