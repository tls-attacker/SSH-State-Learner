package de.rub.nds.sshstatelearner.environment.cli

import com.beust.jcommander.JCommander
import com.beust.jcommander.ParameterException
import de.rub.nds.sshstatelearner.environment.cli.args.ArgsEnvironmentGeneral
import de.rub.nds.sshstatelearner.environment.cli.args.CommandStartAndroidSshClientLearning
import de.rub.nds.sshstatelearner.environment.cli.args.CommandStartServerForFingerprint
import de.rub.nds.sshstatelearner.environment.cli.args.EnvironmentCommand
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
 * Parses the CLI arguments using JCommander. If the help flag is set, it displays the usage and exits the application.
 */
private fun parseArgs(args: Array<out String>, availableEnvironmentCommands: List<EnvironmentCommand>): JCommander {
    try {
        val jCommandBuilder = JCommander.newBuilder().apply {
            addObject(ArgsEnvironmentGeneral)
            for (environmentCommand in availableEnvironmentCommands) {
                addCommand(environmentCommand)
            }
            args(args)
        }
        val cliArgs = jCommandBuilder.build()
        if (args.isEmpty() || ArgsEnvironmentGeneral.help) {
            cliArgs.usage()
            exitProcess(0)
        }
        return cliArgs
    } catch (e: ParameterException) {
        println(e.message)
        exitProcess(0)
    }
}

/**
 * Parses the CLI arguments using JCommander. Determined the EnvironmentCommand to start.
 */
private fun handleArgs(args: Array<out String>): EnvironmentCommand {
    val availableEnvironmentCommands: List<EnvironmentCommand> = listOf(
        CommandStartServerForFingerprint,
        CommandStartAndroidSshClientLearning
    )
    val cliArgs = parseArgs(args, availableEnvironmentCommands)
    val chosenEnvironmentCommand =
        availableEnvironmentCommands.find { it.getCommandName().equals(cliArgs.parsedCommand) }
    if (chosenEnvironmentCommand != null) {
        return chosenEnvironmentCommand
    } else {
        println("Please use a command!")
        cliArgs.usage()
        exitProcess(0)
    }
}

fun main(args: Array<out String>) {
    val environmentCommand = handleArgs(args)
    prepareJCE()

    val environmentManager = environmentCommand.getEnvironmentManager().apply {
        setUp()
        performLearning()
        setDown()
    }
}