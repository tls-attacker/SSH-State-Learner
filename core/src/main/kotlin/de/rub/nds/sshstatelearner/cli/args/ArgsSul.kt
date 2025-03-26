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
import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.constants.SulType
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.constants.ProtocolStage
import de.rub.nds.sshstatelearner.sul.SshSul

/**
 * This object contains all arguments for the JCommander CLI parser which change the behaviour of the SUL itself.
 * This includes connection parameters, protocol stage and key exchange algorithm to use.
 */
object ArgsSul {
    @Parameter(names = ["--name"], description = "Human-readable name of the target SSH server (i. e. SSH server implementation and version)", order = 10)
    var name: String = "Unspecified SSH Server"
        private set

    @Parameter(names = ["--hostname", "-h"], description = "Hostname of the system where the target SSH server is running", order = 11)
    var hostname: String = "localhost"
        private set

    @Parameter(names = ["--ports", "--port", "-p"], description = "Port(s) on which the target SSH server is listening for incoming connection. If multiple ports are specified (comma-separated or range of ports), the learner will perform parallel queries.", listConverter = PortSplitter::class, order = 12)
    var port: List<Int> = listOf(22)
        private set

    @Parameter(names = ["--timeout", "-t"], description = "Timeout in milliseconds when executing a single symbol", order = 13)
    var timeout: Long = SshSul.DEFAULT_SUL_TIMEOUT
        private set

    @Parameter(names = ["--reset-delay"], description = "Delay in milliseconds during reset of a SUL instance", order = 14)
    var resetDelay: Long = SshSul.DEFAULT_SUL_RESET_DELAY
        private set

    @Parameter(names = ["--stage"], description = "The SSH protocol stage whose state machine is to be extracted", order = 15)
    var protocolStage: ProtocolStage = SshSul.DEFAULT_PROTOCOL_STAGE
        private set

    @Parameter(names = ["--kex"], description = "The SSH key exchange method to use. If the alphabet is not specified and the TRANSPORT protocol stage is about to be learned, it derives the alphabet from the provided kex algorithm", order = 16)
    var kexAlgorithm: KeyExchangeAlgorithm = SshSul.DEFAULT_KEX_ALGORITHM
        private set

    @Parameter(names = ["--alphabet"], description = "A comma-separated list of SshSymbol names to use as the alphabet. If not specified, the alphabet is derived from the protocol stage and the key exchange algorithm", listConverter = SshSymbolSplitter::class, order = 17)
    var alphabet: List<SshSymbol>? = null
        private set

    @Parameter(
        names = ["--sul-type"],
        description = "Specifies whether the SUL is a client or a server.",
        order = 18
    )
    var sulType: SulType = SulType.SERVER
        private set

    @Parameter(names = ["--strict-kex"], description = "If set to true, the SUL will offer the strict key exchange protocol extension.", order = 19)
    var strictKex: Boolean = SshSul.DEFAULT_STRICT_KEX_ENABLED
        private set
}
