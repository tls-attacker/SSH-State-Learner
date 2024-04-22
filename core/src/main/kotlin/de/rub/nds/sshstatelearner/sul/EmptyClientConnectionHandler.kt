package de.rub.nds.sshstatelearner.sul

class EmptyClientConnectionHandler : ClientConnectionHandler {
    override fun subscribeForConnection() {

    }

    override fun getPort(): Int {
        return -1
    }

}