package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.sul.SshServerForFingerprint

class OnlyServerForFingerprintManager(val port: Int) : EnvironmentManager() {

    override fun setUp() {
        //Nothing
    }

    override fun performLearning() {

        val sshServerForFingerprint = SshServerForFingerprint(port)
        sshServerForFingerprint.execute()
        sshServerForFingerprint.close()
    }

    override fun setDown() {
        //Nothing
    }

}