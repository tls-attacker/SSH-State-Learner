package de.rub.nds.sshstatelearner.android.cli

import com.beust.jcommander.JCommander
import com.beust.jcommander.ParameterException
import de.rub.nds.sshstatelearner.android.cli.args.ArgsAndroidGeneral
import de.rub.nds.sshstatelearner.android.controller.util.AndroidSSHClientControllerFactory
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

fun main(vararg args: String) {
    handleArgs(args)
    val androidSSHController = AndroidSSHClientControllerFactory.getClientController(ArgsAndroidGeneral)
    with(androidSSHController) {
        installApp()
        setSettingsInApp()
        connectToGetFingerprint()
        while (true) { // do it forever
            oneConnectForStateLearning()
        }
    }
}