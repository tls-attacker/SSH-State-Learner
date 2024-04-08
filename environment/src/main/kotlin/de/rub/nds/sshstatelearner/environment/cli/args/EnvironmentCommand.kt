package de.rub.nds.sshstatelearner.environment.cli.args

import de.rub.nds.sshstatelearner.environment.manager.EnvironmentManager

interface EnvironmentCommand {
    fun getCommandName(): String

    fun getEnvironmentManager(): EnvironmentManager
}