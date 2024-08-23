package de.rub.nds.sshstatelearner.android.controller.util

import de.rub.nds.sshstatelearner.android.cli.args.ArgsAndroidGeneral
import de.rub.nds.sshstatelearner.android.controller.AndroidSSHClientController
import de.rub.nds.sshstatelearner.android.controller.ConnectBotController
import de.rub.nds.sshstatelearner.android.controller.JuiceSSHController
import de.rub.nds.sshstatelearner.android.controller.TermiusController
import de.rub.nds.sshstatelearner.android.controller.constants.AndroidSshClientTyp

/**
 * Class creates the corresponding controller from a configurations.
 */
object AndroidSSHClientControllerFactory {

    /**
     * creates the corresponding controller from a configurations
     */
    fun getClientController(
        androidSshClientTyp: AndroidSshClientTyp,
        ipToAppium: String,
        portToAppium: Int,
        ipToSshServer: String,
        portToSshServer: Int,
        pathToApks: List<String>,
        udid: String
    ): AndroidSSHClientController = when (androidSshClientTyp) {
        AndroidSshClientTyp.INVALID -> throw UnsupportedOperationException("This State is unsupported")

        AndroidSshClientTyp.TERMIUS -> TermiusController(
            ipToAppium, portToAppium, ipToSshServer,
            portToSshServer,
            pathToApks,
            udid
        )

        AndroidSshClientTyp.CONNECT_BOT -> ConnectBotController(
            ipToAppium,
            portToAppium,
            ipToSshServer,
            portToSshServer,
            pathToApks,
            udid
        )

        AndroidSshClientTyp.JUICE_SSH -> JuiceSSHController(
            ipToAppium,
            portToAppium,
            ipToSshServer,
            portToSshServer,
            pathToApks,
            udid
        )
    }

    /**
     * creates the corresponding controller from a configurations
     */
    fun getClientController(argsAndroidGeneral: ArgsAndroidGeneral): AndroidSSHClientController =
        getClientController(
            argsAndroidGeneral.androidSshClientTyp,
            argsAndroidGeneral.ipToAppium,
            argsAndroidGeneral.portToAppium,
            argsAndroidGeneral.ipToSshServer,
            argsAndroidGeneral.portToSshServer,
            argsAndroidGeneral.pathToApks,
            argsAndroidGeneral.udid
        )
}