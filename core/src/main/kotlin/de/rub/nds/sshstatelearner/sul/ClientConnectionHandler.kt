package de.rub.nds.sshstatelearner.sul

interface ClientConnectionHandler {
    fun subscribeForConnection()
    fun getPort(): Int
}