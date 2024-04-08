package de.rub.nds.sshstatelearner.environment.cli.args

import com.beust.jcommander.Parameter

object ArgsEnvironmentGeneral {
    @Parameter(names = ["--help"], help = true, description = "Print this help screen", order = 0)
    var help: Boolean = false
        private set

}