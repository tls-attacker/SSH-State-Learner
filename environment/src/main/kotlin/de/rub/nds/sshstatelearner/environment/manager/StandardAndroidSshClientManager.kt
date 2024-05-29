package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.config.ConfigAndroidClientSul
import de.rub.nds.sshstatelearner.config.ConfigGeneral
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSulProxy
import de.rub.nds.sshstatelearner.sul.SshClientWorker
import de.rub.nds.sshstatelearner.sul.SshSul
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class StandardAndroidSshClientManager(
    configGeneral: ConfigGeneral,
    private val configAndroidClientSul: ConfigAndroidClientSul
) :
    StandardSshManager(configGeneral) {

    private val androidClientConnectionHandlers: MutableList<AndroidClientConnectionHandler> = mutableListOf()
    private val sshClientWorker = SshClientWorker()

    override fun setUp() {
        fun createConnectionHandlersForAndroidClients() {
            runBlocking {
                for (connectionInfo in configAndroidClientSul.androidConnectionInfos) {
                    val androidClientConnectionHandler = AndroidClientConnectionHandler(
                        configAndroidClientSul.androidSshClientTyp,
                        connectionInfo.ipToAppium,
                        connectionInfo.portToAppium,
                        connectionInfo.ipToServer,
                        connectionInfo.portToServer,
                        connectionInfo.pathToApks,
                        connectionInfo.uuid
                    )
                    androidClientConnectionHandlers.add(
                        androidClientConnectionHandler
                    )
                    launch(Dispatchers.IO) { androidClientConnectionHandler.init() }
                }
            }
        }

        fun createNetworkSshClientSulsAndAddItToClientWorker() {
            val suls = mutableListOf<NetworkSshClientSul>()
            for (clientConnectionHandler in androidClientConnectionHandlers) {
                suls.add(
                    NetworkSshClientSul(
                        configAndroidClientSul.name,
                        clientConnectionHandler.getPort(),
                        configAndroidClientSul.timeout,
                        configAndroidClientSul.resetDelay,
                        configAndroidClientSul.protocolStage,
                        configAndroidClientSul.kexAlgorithm,
                        clientConnectionHandler
                    )
                )
            }
            sshClientWorker.init(suls)
        }

        createConnectionHandlersForAndroidClients()
        createNetworkSshClientSulsAndAddItToClientWorker()
    }

    override fun getCountOfParallelSuls(): Int = configAndroidClientSul.androidConnectionInfos.size

    override fun getSul(): SshSul = NetworkSshClientSulProxy(
        configAndroidClientSul.name,
        configAndroidClientSul.timeout,
        configAndroidClientSul.resetDelay,
        configAndroidClientSul.protocolStage,
        configAndroidClientSul.kexAlgorithm,
        sshClientWorker
    )

    override fun setDown() {
        /* Do Nothing */
    }

}