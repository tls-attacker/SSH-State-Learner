package de.rub.nds.sshstatelearner.sul.handler

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/**
 * This class starts the local client and establishes a connection to the SUL.
 */
class LocalSshClientConnectionHandler(
    private val ip: String,
    override val port: Int,
    private val preLearnFingerprintAcceptance: Boolean
) : ClientConnectionHandler {
    private val acceptFingerprintOption = "-o StrictHostKeyChecking=accept-new"
    private val process: ProcessBuilder =
        ProcessBuilder(
            "ssh",
            "attacker@$ip",
            if (preLearnFingerprintAcceptance) acceptFingerprintOption else "",
            "-p $port"
        )

    private val jobs: MutableList<Process> = mutableListOf()

    override fun init() = Unit

    override suspend fun connect() {
        delay(10)
        jobs.add(withContext(Dispatchers.IO) {
            process.start()
        })
    }

    override fun exit() {
        jobs.forEach { if (it.isAlive) it.destroy() }
    }
}