package de.rub.nds.sshstatelearner.environment.cli.args

import com.beust.jcommander.Parameter
import com.beust.jcommander.Parameters
import de.rub.nds.sshstatelearner.environment.manager.EnvironmentManager
import de.rub.nds.sshstatelearner.environment.manager.OnlyServerForFingerprintManager

@Parameters(
    commandNames = [CommandStartServerForFingerprint.COMMAND_NAME],
    commandDescription = "Starts a server to retrieve the fingerprint "
)
object CommandStartServerForFingerprint : EnvironmentCommand {
    const val COMMAND_NAME = "start-server-for-fingerprint"

    @Parameter(
        names = ["--port"],
        description = "The port of the server",
        order = 1
    )
    var port = 48223
    override fun getCommandName(): String {
        return COMMAND_NAME
    }

    override fun getEnvironmentManager(): EnvironmentManager {
        return OnlyServerForFingerprintManager(port)
    }
}