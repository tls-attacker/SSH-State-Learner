package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.config.ConfigGeneral
import de.rub.nds.sshstatelearner.config.ConfigServerSul
import de.rub.nds.sshstatelearner.constants.ExecutorType
import de.rub.nds.sshstatelearner.sul.NetworkSshServerSul
import de.rub.nds.sshstatelearner.sul.SshSul

class StandardSshServerManager(configGeneral: ConfigGeneral, val configServerSul: ConfigServerSul) :
    StandardSshManager(configGeneral) {

    override fun setUp() {
    }

    override fun getSul(): SshSul = when (configGeneral.executorType) {
        ExecutorType.NETWORK -> {
            NetworkSshServerSul(
                configServerSul.name,
                configServerSul.hostname,
                configServerSul.port,
                configServerSul.timeout,
                configServerSul.resetDelay,
                configServerSul.protocolStage,
                configServerSul.kexAlgorithm
            )
        }
    }

    override fun getCountOfParallelSuls(): Int = 1

    override fun setDown() {
        /* Do Nothing */
    }
}