package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.config.ConfigAndroidClientSul
import de.rub.nds.sshstatelearner.config.ConfigGeneral
import de.rub.nds.sshstatelearner.sul.NetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.PooledNetworkSshClientSul
import de.rub.nds.sshstatelearner.sul.SshClientWorker
import de.rub.nds.sshstatelearner.sul.SshSul
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.FileWriter
import java.io.PrintWriter

/**
 * Enables the SML for Android clients
 */
class StandardAndroidSshClientManager(
    configGeneral: ConfigGeneral,
    private val configAndroidClientSul: ConfigAndroidClientSul
) :
    StandardSshManager(configGeneral) {

    private val androidClientConnectionHandlers: MutableList<AndroidClientConnectionHandler> = mutableListOf()
    private val sshClientWorker = SshClientWorker()

    override fun setUp() {
        /**
         * Creates the `AndroidClientConnectionHandler` and performs an initialization.
         * This allows the `AndroidSSHClientController` to establish a connection to the emulator, install the app,
         * configure settings, and, if desired, accept the host key.
         */
        fun createConnectionHandlersForAndroidClients() {
            runBlocking {
                for (connectionInfo in configAndroidClientSul.androidConnectionInfos) {
                    val androidClientConnectionHandler = AndroidClientConnectionHandler(
                        configAndroidClientSul.androidSshClientTyp,
                        connectionInfo.ipToAppium,
                        connectionInfo.portToAppium,
                        connectionInfo.ipToServer,
                        connectionInfo.portToServer,
                        configAndroidClientSul.pathToApks,
                        connectionInfo.uuid,
                        configAndroidClientSul.preLearnFingerprintAcceptance
                    )
                    androidClientConnectionHandlers.add(
                        androidClientConnectionHandler
                    )
                    launch(Dispatchers.IO) { androidClientConnectionHandler.init() }
                }
            }
        }

        /**
         *  Passes the ConnectionHandler to the SUL so that it can request the connection when needed
         */
        fun createNetworkSshClientSulsAndAddItToClientWorker() {
            val suls = mutableListOf<NetworkSshClientSul>()
            for (clientConnectionHandler in androidClientConnectionHandlers) {
                suls.add(
                    NetworkSshClientSul(
                        configAndroidClientSul.name,
                        clientConnectionHandler.port,
                        configAndroidClientSul.timeout,
                        configAndroidClientSul.resetDelay,
                        configAndroidClientSul.protocolStage,
                        configAndroidClientSul.kexAlgorithm,
                        configAndroidClientSul.strictKex,
                        false,
                        false,
                        false,
                        -1,
                        100,
                        configAndroidClientSul.enableEncryptionOnNewKeysMessage,
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

    override fun getSul(): SshSul = PooledNetworkSshClientSul(
        configAndroidClientSul.name,
        configAndroidClientSul.timeout,
        configAndroidClientSul.resetDelay,
        configAndroidClientSul.protocolStage,
        configAndroidClientSul.kexAlgorithm,
        sshClientWorker
    )

    override fun setDown() {
        androidClientConnectionHandlers.forEach { it.exit() }
        sshClientWorker.exit()
    }

    override fun addAdditionalStatistics(fileWriter: FileWriter) {
        PrintWriter(fileWriter).run {
            println("Time total idle Time: ${sshClientWorker.getTotalIdleTime().inWholeMilliseconds} milliseconds")
            println("Time total work Time: ${sshClientWorker.getTotalWorkTime().inWholeMilliseconds} milliseconds")
            println("Time total init Time: ${sshClientWorker.getTotalInitTime().inWholeMilliseconds} milliseconds")
        }
    }

}