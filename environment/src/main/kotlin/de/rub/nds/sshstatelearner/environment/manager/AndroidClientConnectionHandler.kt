package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.android.controller.AndroidSSHClientController
import de.rub.nds.sshstatelearner.android.controller.constants.AndroidSshClientTyp
import de.rub.nds.sshstatelearner.android.controller.util.AndroidSSHClientControllerFactory
import de.rub.nds.sshstatelearner.sul.ClientConnectionHandler
import de.rub.nds.sshstatelearner.sul.SshServerForFingerprint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

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
    private val androidSSHClientController: AndroidSSHClientController

    override fun getPort(): Int = androidSSHClientController.portToServer

    init {
        androidSSHClientController = AndroidSSHClientControllerFactory.getClientController(
            androidSshClientTyp,
            ipToAppium,
            portToAppium,
            ipToSshServer,
            portToSshServer,
            pathToApks,
            udid
        )
    }

    override fun exit() {
        androidSSHClientController.quit()
    }

    override fun init() {
        try {
            runBlocking() {
                val sshServerForFingerprint = SshServerForFingerprint(getPort())
                val fingerprint = launch(Dispatchers.IO) {
                    // 1.SETUP SERVER for fingerprint
                    sshServerForFingerprint.execute()
                    sshServerForFingerprint.close()
                }

                val fingerprintAndroid = launch(Dispatchers.IO) {
                    androidSSHClientController.installApp()
                    androidSSHClientController.connectToGetFingerprint(preLearnFingerprintAcceptance)
                }
                try {
                    joinAll(fingerprint, fingerprintAndroid)
                } finally {
                    if (!fingerprint.isCompleted) sshServerForFingerprint.close()
                    if (!fingerprintAndroid.isCompleted) androidSSHClientController.quit()
                }
            }
        } catch (e: Exception) {
            throw e
        }
    }

    override suspend fun subscribeForConnection() {
        androidSSHClientController.oneConnectForStateLearning()
    }
}
