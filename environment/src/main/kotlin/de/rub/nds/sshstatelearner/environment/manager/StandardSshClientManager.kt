package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.config.ConfigClientSul
import de.rub.nds.sshstatelearner.config.ConfigGeneral
import de.rub.nds.sshstatelearner.sul.handler.ClientConnectionHandler
import de.rub.nds.sshstatelearner.sul.handler.LocalSshClientConnectionHandler
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.PooledNetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.SshClientWorker
import de.rub.nds.sshstatelearner.sul.SshSul
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.FileWriter
import java.io.PrintWriter

class StandardSshClientManager(configGeneral: ConfigGeneral, private val configClientSul: ConfigClientSul) :
    StandardSshManager(configGeneral) {

    private val clientConnectionHandlers: MutableList<ClientConnectionHandler> = mutableListOf()
    private val sshClientWorker = SshClientWorker()

    override fun setUp() {
        fun createConnectionHandlersForClients() {
            runBlocking {
                for (connectionInfo in configClientSul.connectionInfos) {
                    val connectionHandler = LocalSshClientConnectionHandler(
                        connectionInfo.ipToServer,
                        connectionInfo.portToServer,
                        configClientSul.preLearnFingerprintAcceptance
                    )
                    clientConnectionHandlers.add(
                        connectionHandler
                    )
                    launch(Dispatchers.IO) { connectionHandler.init() }
                }
            }
        }

        fun createNetworkSshClientSulsAndAddItToClientWorker() {
            val suls = mutableListOf<NetworkSshClientSul>()
            for (clientConnectionHandler in clientConnectionHandlers) {
                suls.add(
                    NetworkSshClientSul(
                        configClientSul.name,
                        clientConnectionHandler.port,
                        configClientSul.timeout,
                        configClientSul.resetDelay,
                        configClientSul.protocolStage,
                        configClientSul.kexAlgorithm,
                        configClientSul.strictKex,
                        false,
                        false,
                        false,
                        -1,
                        100,
                        configClientSul.enableEncryptionOnNewKeysMessage,
                        clientConnectionHandler
                    )
                )
            }
            sshClientWorker.init(suls)
        }

        createConnectionHandlersForClients()
        createNetworkSshClientSulsAndAddItToClientWorker()
    }

    override fun getCountOfParallelSuls(): Int = configClientSul.connectionInfos.size

    override fun getSul(): SshSul = PooledNetworkSshClientSul(
        configClientSul.name,
        configClientSul.timeout,
        configClientSul.resetDelay,
        configClientSul.protocolStage,
        configClientSul.kexAlgorithm,
        sshClientWorker
    )

    override fun setDown() {
        sshClientWorker.exit()
        clientConnectionHandlers.forEach { it.exit() }
    }

    override fun addAdditionalStatistics(fileWriter: FileWriter) {
        PrintWriter(fileWriter).run {
            println("Time total idle Time: ${sshClientWorker.getTotalIdleTime().inWholeMilliseconds} milliseconds")
            println("Time total work Time: ${sshClientWorker.getTotalWorkTime().inWholeMilliseconds} milliseconds")
            println("Time total init Time: ${sshClientWorker.getTotalInitTime().inWholeMilliseconds} milliseconds")
        }
    }

}