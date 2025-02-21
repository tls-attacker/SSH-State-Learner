package de.rub.nds.sshstatelearner.environment.cli

import com.beust.jcommander.JCommander
import com.beust.jcommander.ParameterException
import de.rub.nds.sshstatelearner.config.ConfigAndroidClientSul
import de.rub.nds.sshstatelearner.config.ConfigClientSul
import de.rub.nds.sshstatelearner.config.ConfigHelper
import de.rub.nds.sshstatelearner.config.ConfigServerSul
import de.rub.nds.sshstatelearner.environment.cli.args.ArgsEnvironmentGeneral
import de.rub.nds.sshstatelearner.environment.manager.EnvironmentManager
import de.rub.nds.sshstatelearner.environment.manager.StandardAndroidSshClientManager
import de.rub.nds.sshstatelearner.environment.manager.StandardSshClientManager
import de.rub.nds.sshstatelearner.environment.manager.StandardSshServerManager
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.File
import java.security.Security
import kotlin.system.exitProcess

/**
 * Prepares the JCE (Java Cryptographic Extension) by adding the BouncyCastle provider.
 */
private fun prepareJCE() {
    Security.addProvider(BouncyCastleProvider())
}

/**
 * Parses the CLI arguments using JCommander. Determined the EnvironmentCommand to start.
 */
private fun handleArgs(args: Array<out String>) {
    try {
        val cliArgs = JCommander.newBuilder()
            .addObject(ArgsEnvironmentGeneral)
            .args(args)
            .build()
        if (args.isEmpty() || ArgsEnvironmentGeneral.help) {
            cliArgs.usage()
            exitProcess(0)
        }
        if (ArgsEnvironmentGeneral.pathToConfigJson.isNotBlank()
            && ArgsEnvironmentGeneral.pathToConfigDirectory.isNotBlank()
        ) {
            cliArgs.console.println("Use only one of these arguments.")
        }
    } catch (e: ParameterException) {
        println(e.message)
        exitProcess(0)
    }
}

fun main(args: Array<out String>) {
    handleArgs(args)
    prepareJCE()

    val configHelper = ConfigHelper()
    if (ArgsEnvironmentGeneral.pathToConfigJson.isNotBlank()) {
        runSML(configHelper, ArgsEnvironmentGeneral.pathToConfigJson)
    } else {
        val file = File(ArgsEnvironmentGeneral.pathToConfigDirectory)
        if (file.isDirectory) {
            file.listFiles { _, fileName -> fileName.contains(".json") }?.forEach {
                runSML(configHelper, it.absolutePath)
            }
        }
    }
}

/**
 * Starts a STL run with the configuration file
 */
private fun runSML(configHelper: ConfigHelper, absolutePath: String) {
    val configGeneral = configHelper.readConfig(absolutePath)
    val configSulConfig = configGeneral.sulConfig
    val environmentManager: EnvironmentManager = when (configSulConfig) {
        is ConfigServerSul -> {
            StandardSshServerManager(configGeneral, configSulConfig)
        }

        is ConfigClientSul -> {
            StandardSshClientManager(configGeneral, configSulConfig)
        }

        is ConfigAndroidClientSul -> {
            StandardAndroidSshClientManager(configGeneral, configSulConfig)
        }

        else -> {
            throw IllegalStateException("Unknown config sul type: ${configSulConfig::class.java.canonicalName}")
        }
    }

    environmentManager.apply {
        setUp()
        performLearning()
        setDown()
    }
}