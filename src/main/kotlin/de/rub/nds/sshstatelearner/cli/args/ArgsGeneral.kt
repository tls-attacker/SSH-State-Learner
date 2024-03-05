/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.cli.args

import com.beust.jcommander.Parameter
import de.rub.nds.sshstatelearner.constants.ExecutorType

/**
 * This object contains all arguments for the JCommander CLI parser that do not fall in a specific category.
 */
object ArgsGeneral {
    @Parameter(names = ["--help"], help = true, description = "Print this help screen", order = 0)
    var help: Boolean = false
        private set

    @Parameter(names = ["-o", "--output"], description = "Folder to output the extracted state machine to", order = 1)
    var output: String = "out/"
        private set

    @Parameter(names = ["--executor"], description = "Executor to use", order = 2)
    var executor: ExecutorType = ExecutorType.NETWORK
        private set
}
