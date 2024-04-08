package de.rub.nds.sshstatelearner.android.cli

import com.beust.jcommander.JCommander
import com.beust.jcommander.ParameterException
import de.rub.nds.sshstatelearner.android.cli.args.ArgsAndroidGeneral
import de.rub.nds.sshstatelearner.android.controller.AndroidSSHClientController
import de.rub.nds.sshstatelearner.android.controller.JuiceSSHController
import de.rub.nds.sshstatelearner.android.controller.constants.AndroidSshClientTyp
import kotlin.system.exitProcess

/**
 * Parses the CLI arguments using JCommander. If the help flag is set, it displays the usage and exits the application.
 */
private fun handleArgs(args: Array<out String>) {
    try {
        val cliArgs = JCommander.newBuilder()
            .addObject(ArgsAndroidGeneral)
            .args(args)
            .build()
        if (args.isEmpty() || ArgsAndroidGeneral.help) {
            cliArgs.usage()
            exitProcess(0)
        }
    } catch (e: ParameterException) {
        println(e.message)
        exitProcess(0)
    }
}

private fun getClientController(): AndroidSSHClientController = when (ArgsAndroidGeneral.androidSshClientTyp) {
    AndroidSshClientTyp.INVALID -> throw UnsupportedOperationException("This State is unsupported")
    AndroidSshClientTyp.TERMIUS -> TODO()
    AndroidSshClientTyp.CONNECT_BOT -> TODO()
    AndroidSshClientTyp.JUICE_SSH -> JuiceSSHController(
        ArgsAndroidGeneral.ipToAppium,
        ArgsAndroidGeneral.portToAppium,
        ArgsAndroidGeneral.ipToSshServer,
        ArgsAndroidGeneral.portToSshServer,
        ArgsAndroidGeneral.pathToApks ?: listOf(),
        ArgsAndroidGeneral.udid
    )
}

fun main(vararg args: String) {
    handleArgs(args)
    val androidSSHController = getClientController()
    with(androidSSHController) {
        installApp()
        connectToGetFingerprint()
        connectForStateLearning()
    }
}