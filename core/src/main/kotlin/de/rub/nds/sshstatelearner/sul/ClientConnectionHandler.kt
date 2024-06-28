package de.rub.nds.sshstatelearner.sul

interface ClientConnectionHandler {
    fun init()
    fun exit()
    suspend fun subscribeForConnection()
    fun getPort(): Int
}