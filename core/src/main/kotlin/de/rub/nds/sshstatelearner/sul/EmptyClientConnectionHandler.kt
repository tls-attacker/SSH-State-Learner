package de.rub.nds.sshstatelearner.sul

class EmptyClientConnectionHandler : ClientConnectionHandler {
    override fun init() {

    }

    override fun exit() {
        
    }

    override suspend fun subscribeForConnection() {

    }

    override fun getPort(): Int {
        return -1
    }

}