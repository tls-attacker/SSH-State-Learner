package de.rub.nds.sshstatelearner.environment.manager

import de.rub.nds.sshstatelearner.cli.args.ArgsGeneral
import de.rub.nds.sshstatelearner.cli.args.ArgsSul
import de.rub.nds.sshstatelearner.config.ConfigGeneral
import de.rub.nds.sshstatelearner.config.ConfigServerSul
import de.rub.nds.sshstatelearner.constants.ExecutorType
import de.rub.nds.sshstatelearner.sul.NetworkSshServerSul
import de.rub.nds.sshstatelearner.sul.SshSul

class StandardSshServerManager(configGeneral: ConfigGeneral, val configServerSul: ConfigServerSul) :
    StandardSshManager(configGeneral) {

    override fun setUp() {
    }

    override fun getSul(): SshSul = when (ArgsGeneral.executor) {
//        ExecutorType.NYX -> NyxSshSul(
//            ArgsSul.name,
//            "/home/fabian/Workspace/targets/packed_targets/nyx_openssh",
//            "/tmp/nyx",
//            0,
//            ArgsSul.timeout,
//            ArgsSul.resetDelay,
//            ArgsSul.protocolStage,
//            ArgsSul.kexAlgorithm
//        )

        ExecutorType.NYX, ExecutorType.NETWORK ->
            NetworkSshServerSul(
                ArgsSul.name,
                ArgsSul.hostname,
                ArgsSul.port,
                ArgsSul.timeout,
                ArgsSul.resetDelay,
                ArgsSul.protocolStage,
                ArgsSul.kexAlgorithm
            )

    }

    override fun getCountOfParallelSuls(): Int = 1

    override fun setDown() {
        /* Do Nothing */
    }

}