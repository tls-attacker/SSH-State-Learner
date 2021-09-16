package de.rub.nds.sshstatelearner.analysis.analyzer

import de.rub.nds.sshstatelearner.StateMachine
import de.rub.nds.sshstatelearner.analysis.data.GraphDetails
import de.rub.nds.sshstatelearner.analysis.classifier.Classifier
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

abstract class Analyzer<S, I, T, O>(protected open val graphDetails: GraphDetails<S, I, T>) {
    companion object {
        /**
         * Logger for the Analyzer class.
         */
        private val LOGGER: Logger = LogManager.getLogger()
    }

    protected val classifiers = listOf<Classifier<S, I, T, O>>()

    // TODO: Gather and return vulnerabilities when classifiers are fully implemented
    fun findVulnerabilities(machine: StateMachine<S, I, T, O>) {
        for (classifier in classifiers) {
            try {
                classifier.getVulnerabilitiesOfClass(machine)
            } catch (e: Exception) {
                LOGGER.error("Caught an error while searching for vulnerabilities. Classifier ${classifier::class.simpleName} threw an unexpected exception.", e)
            }
        }
    }
}