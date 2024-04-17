package de.rub.nds.sshstatelearner.environment.cli.args

import com.beust.jcommander.Parameters
import com.beust.jcommander.ParametersDelegate
import de.rub.nds.sshstatelearner.android.cli.args.ArgsAndroidGeneral
import de.rub.nds.sshstatelearner.environment.manager.EnvironmentManager
import de.rub.nds.sshstatelearner.environment.manager.StandardAndroidSshManager

@Parameters(
    commandNames = [CommandStartAndroidSshClientLearning.COMMAND_NAME],
    commandDescription = "Starts a server to retrieve the fingerprint "
)
object CommandStartAndroidSshClientLearning : EnvironmentCommand {
    const val COMMAND_NAME = "start-android-ssh-client-learning"

    @ParametersDelegate
    val argsAndroidGeneral = ArgsAndroidGeneral
    override fun getCommandName(): String {
        return COMMAND_NAME
    }

    override fun getEnvironmentManager(): EnvironmentManager {
        return StandardAndroidSshManager(argsAndroidGeneral)
    }
}