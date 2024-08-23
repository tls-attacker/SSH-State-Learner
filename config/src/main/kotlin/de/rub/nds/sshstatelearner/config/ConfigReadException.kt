package de.rub.nds.sshstatelearner.config

/**
 * Class in the event that an error occurs when reading a configuration class.
 */
class ConfigReadException : Exception {
    constructor(message: String) : super(message) {
    }

    constructor(message: String, cause: Throwable) : super(message, cause) {
    }
}