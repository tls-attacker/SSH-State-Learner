package de.rub.nds.sshstatelearner.sul

import kotlinx.coroutines.delay

class LocalSSHClientConnectionHandler(private val ip: String, private val port: Int) : ClientConnectionHandler {
    private val process: ProcessBuilder =
        ProcessBuilder("ssh", "attacker@$ip", "-o StrictHostKeyChecking=accept-new", "-p $port")

    private val jobs: MutableList<Process> = mutableListOf()

    override fun init() {
        // Nothing to init
    }

    override fun exit() {
        jobs.forEach { if (it.isAlive) it.destroy() }
    }

    override suspend fun subscribeForConnection() {
        delay(10)
        jobs.add(process.start())
    }

    override fun getPort(): Int {
        return port
    }
}