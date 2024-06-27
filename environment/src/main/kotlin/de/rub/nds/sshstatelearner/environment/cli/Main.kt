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
    } catch (e: ParameterException) {
        println(e.message)
        exitProcess(0)
    }
}

fun main(args: Array<out String>) {
    handleArgs(args)
    prepareJCE()

    val configHelper = ConfigHelper()
    val configGeneral = configHelper.readConfig(ArgsEnvironmentGeneral.pathToConfigJson)
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