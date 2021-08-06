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

object ArgsSul {
    @Parameter(names = ["--hostname"], description = "Hostname of the system where the target SSH server is running")
    var hostname: String = "localhost"
        private set

    @Parameter(names = ["--port"], description = "Port on which the target SSH server is listening for incoming connection")
    var port: Int = 22
        private set

    @Parameter(names = ["--timeout"], description = "Timeout in milliseconds when reading incoming traffic from the network socket")
    var timeout: Long = 1000
        private set

    @Parameter(names = ["--resetDelay"], description = "Delay in milliseconds during reset of a SUL instance")
    var resetDelay: Long = 0
        private set
}
