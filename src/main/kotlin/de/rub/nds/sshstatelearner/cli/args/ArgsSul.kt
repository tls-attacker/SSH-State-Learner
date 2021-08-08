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
import de.rub.nds.sshstatelearner.sul.SshSul
import de.rub.nds.sshstatelearner.sul.symbols.SshSymbol

object ArgsSul {
    @Parameter(names = ["--hostname", "-h"], description = "Hostname of the system where the target SSH server is running", order = 10)
    var hostname: String = "localhost"
        private set

    @Parameter(names = ["--port", "-p"], description = "Port on which the target SSH server is listening for incoming connection", order = 11)
    var port: Int = 22
        private set

    @Parameter(names = ["--timeout", "-t"], description = "Timeout in milliseconds when reading incoming traffic from the network socket", order = 12)
    var timeout: Long = SshSul.DEFAULT_TRANSPORT_HANDLER_TIMEOUT
        private set

    @Parameter(names = ["--resetDelay"], description = "Delay in milliseconds during reset of a SUL instance", order = 13)
    var resetDelay: Long = SshSul.DEFAULT_SUL_RESET_DELAY
        private set

    @Parameter(names = ["--receiveDelay"], description = "Delay in milliseconds between sending messages and receiving the server response. Larger delays avoid DATA_AVAILABLE socket states while increasing overall runtime", order = 14)
    var receiveDelay: Long = SshSymbol.DEFAULT_RECEIVE_DELAY
        private set
}
