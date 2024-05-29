package de.rub.nds.sshstatelearner.config

class ConfigReadException : Exception {
    constructor(message: String) : super(message) {
    }

    constructor(message: String, cause: Throwable) : super(message, cause) {
    }
}