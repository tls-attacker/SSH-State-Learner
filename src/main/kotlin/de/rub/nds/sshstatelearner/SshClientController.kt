package de.rub.nds.sshstatelearner

class SshClientController(pathToClient: String, params: Array<String>) {

    private val processBuilder = ProcessBuilder(pathToClient, *params)
    private var isFinished = false

    fun run() {
        while (!isFinished) {
            val process = processBuilder.start()
            process.waitFor()
        }
    }

    fun stop() {
        isFinished = true
    }

    fun makeRunnable() {
        isFinished = false
    }
}