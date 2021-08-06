package de.rub.nds.sshstatelearner.util

import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

open class LoggerCompanion {
    protected val LOGGER: Logger = LogManager.getLogger()
}