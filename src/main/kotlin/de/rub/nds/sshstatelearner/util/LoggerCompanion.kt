/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.util

import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

/**
 * A simple companion class providing a logger via the LogManager.getLogger() method.
 */
open class LoggerCompanion {
    protected val LOGGER: Logger = LogManager.getLogger()
}
