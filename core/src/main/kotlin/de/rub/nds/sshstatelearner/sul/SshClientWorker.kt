package de.rub.nds.sshstatelearner.sul

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class SshClientWorker {
    private val scope = CoroutineScope(Dispatchers.IO)
    private val sulToUse = Channel<NetworkSshClientSul>(32)

    fun init(suls: List<NetworkSshClientSul>) {
        runBlocking {
            for (sul in suls) {
                sul.pre()
                sulToUse.send(sul)
            }
        }
    }

    fun getReadySulToUse(): NetworkSshClientSul = runBlocking { sulToUse.receive() }

    fun getSulWasUsed(sul: NetworkSshClientSul) {
        scope.launch {
            sul.post()
            sul.pre()
            sulToUse.send(sul)
        }
    }

}