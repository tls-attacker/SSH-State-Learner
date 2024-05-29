package de.rub.nds.sshstatelearner.sul

interface ClientConnectionHandler {
    fun init()
    suspend fun subscribeForConnection()
    fun getPort(): Int
}