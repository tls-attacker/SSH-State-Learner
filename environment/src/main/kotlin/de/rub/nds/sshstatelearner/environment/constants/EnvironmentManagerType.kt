package de.rub.nds.sshstatelearner.environment.constants

import de.rub.nds.sshstatelearner.environment.cli.args.CommandStartServerForFingerprint

enum class EnvironmentManagerType(val commandName: String?) {
    INVALID(null),
    STANDARD("STANDARD"),
    SERVER_FOR_FINGERPRINT(CommandStartServerForFingerprint.COMMAND_NAME)
}