package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.android.controller.AndroidSSHClientController
import de.rub.nds.sshstatelearner.android.controller.constants.AndroidSshClientTyp
import de.rub.nds.sshstatelearner.android.controller.util.AndroidSSHClientControllerFactory
import de.rub.nds.sshstatelearner.sul.handler.ClientConnectionHandler
import de.rub.nds.sshstatelearner.sul.SimpleSshServer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * This class abstracts the initialization and control of the AndroidSSHClientController
 */
class AndroidClientConnectionHandler(
    private val androidSshClientTyp: AndroidSshClientTyp,
    private val ipToAppium: String,
    private val portToAppium: Int,
    private val ipToSshServer: String,
    private val portToSshServer: Int,
    private val pathToApks: List<String>,
    private val udid: String,
    private val preLearnFingerprintAcceptance: Boolean
) : ClientConnectionHandler {

    private val androidSSHClientController: AndroidSSHClientController = AndroidSSHClientControllerFactory.getClientController(
        androidSshClientTyp,
        ipToAppium,
        portToAppium,
        ipToSshServer,
        portToSshServer,
        pathToApks,
        udid
    )

    override val port: Int
        get() = androidSSHClientController.portToServer

    override fun exit() {
        androidSSHClientController.quit()
    }

    override fun init() {
        try {
            runBlocking {
                val simpleSshServer = SimpleSshServer(port)
                val fingerprint = launch(Dispatchers.IO) {
                    // 1.SETUP SERVER for fingerprint
                    simpleSshServer.execute()
                    simpleSshServer.close()
                }

                val fingerprintAndroid = launch(Dispatchers.IO) {
                    androidSSHClientController.installApp()
                    androidSSHClientController.setSettingsInApp()
                    if (preLearnFingerprintAcceptance) {
                        androidSSHClientController.connectToGetFingerprint()
                    } else {
                        androidSSHClientController.oneConnectForStateLearning()
                    }


                }
                try {
                    joinAll(fingerprint, fingerprintAndroid)
                } finally {
                    if (!fingerprint.isCompleted) simpleSshServer.close()
                    if (!fingerprintAndroid.isCompleted) androidSSHClientController.quit()
                }
            }
        } catch (e: Exception) {
            throw e
        }
    }
    
    override suspend fun connect() {
        androidSSHClientController.oneConnectForStateLearning()
    }
}
