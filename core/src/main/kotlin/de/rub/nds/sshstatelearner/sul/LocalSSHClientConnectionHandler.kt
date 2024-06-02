package de.rub.nds.sshstatelearner.sul

import kotlinx.coroutines.delay

class LocalSSHClientConnectionHandler(private val ip: String, private val port: Int) : ClientConnectionHandler {
    val process: ProcessBuilder =
        ProcessBuilder("ssh", "attacker@$ip", "-o StrictHostKeyChecking=accept-new", "-p $port")

    override fun init() {
        // Nothing to init
    }

    override suspend fun subscribeForConnection() {
        delay(10)
        val job = process.start()
    }

    override fun getPort(): Int {
        return port
    }
}