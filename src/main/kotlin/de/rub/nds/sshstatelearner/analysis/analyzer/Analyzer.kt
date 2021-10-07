/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.analyzer

import de.rub.nds.sshstatelearner.StateMachine
import de.rub.nds.sshstatelearner.analysis.classifier.Classifier
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

abstract class Analyzer<S, I, T, O> {
    companion object {
        /**
         * Logger for the Analyzer class.
         */
        private val LOGGER: Logger = LogManager.getLogger()
    }

    protected val classifiers = mutableListOf<Classifier<S, I, T, O>>()

    // TODO: Gather and return vulnerabilities when classifiers are fully implemented
    fun analyze(machine: StateMachine<S, I, T, O>) {
        for (classifier in classifiers) {
            try {
                classifier.performClassification(machine)
            } catch (e: Exception) {
                LOGGER.error("Caught an error while analyzing the extracted state machine. Classifier ${classifier::class.simpleName} threw an unexpected exception.", e)
            }
        }
    }
}
