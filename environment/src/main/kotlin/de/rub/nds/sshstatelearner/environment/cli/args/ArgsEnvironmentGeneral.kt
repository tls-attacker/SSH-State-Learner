package de.rub.nds.sshstatelearner.environment.cli.args

import com.beust.jcommander.Parameter

object ArgsEnvironmentGeneral {
    @Parameter(names = ["--help"], help = true, description = "Print this help screen", order = 0)
    var help: Boolean = false
        private set

    @Parameter(names = ["--path-to-config-json"], description = "Path to config file", order = 1)
    var pathToConfigJson: String = ""
        private set

    @Parameter(names = ["--path-to-config-directory"], description = "Path to a directory of config files", order = 2)
    var pathToConfigDirectory: String = ""
        private set

}