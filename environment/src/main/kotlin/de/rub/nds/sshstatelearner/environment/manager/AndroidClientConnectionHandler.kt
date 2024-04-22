package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.android.cli.args.ArgsAndroidGeneral
import de.rub.nds.sshstatelearner.android.controller.AndroidSSHClientController
import de.rub.nds.sshstatelearner.android.controller.util.AndroidSSHClientControllerFactory
import de.rub.nds.sshstatelearner.sul.ClientConnectionHandler
import de.rub.nds.sshstatelearner.sul.SshServerForFingerprint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.cancel
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

class AndroidClientConnectionHandler : ClientConnectionHandler {
    private val scope = CoroutineScope(Dispatchers.IO)

    private val androidSSHClientController: AndroidSSHClientController

    override fun getPort(): Int = androidSSHClientController.portToServer

    constructor(udid: String = ArgsAndroidGeneral.udid, portToSshServer: Int = ArgsAndroidGeneral.portToSshServer) {
        androidSSHClientController = AndroidSSHClientControllerFactory.getClientController(
            ArgsAndroidGeneral.androidSshClientTyp,
            ArgsAndroidGeneral.ipToAppium,
            ArgsAndroidGeneral.portToAppium,
            ArgsAndroidGeneral.ipToSshServer,
            portToSshServer,
            ArgsAndroidGeneral.pathToApks,
            udid
        )
    }

    fun init() {
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
                    androidSSHClientController.connectToGetFingerprint()
                }
                try {
                    joinAll(fingerprint, fingerprintAndroid)
                } finally {
                    if (!fingerprint.isCompleted) sshServerForFingerprint.close()
                    if (!fingerprintAndroid.isCompleted) androidSSHClientController.quit()
                }
            }
        } catch (e: Exception) {
            throw IllegalStateException(e.cause)
        }
    }

    fun destroy() = scope.cancel()

    override fun subscribeForConnection() {
        androidSSHClientController.oneConnectForStateLearning()
    }
}
