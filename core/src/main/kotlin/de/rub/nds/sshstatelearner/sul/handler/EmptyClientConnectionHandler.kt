package de.rub.nds.sshstatelearner.sul.handler

class EmptyClientConnectionHandler : ClientConnectionHandler {
    override fun init() = Unit
    override fun exit() = Unit
    override suspend fun connect() = Unit
    override val port: Int = -1
}