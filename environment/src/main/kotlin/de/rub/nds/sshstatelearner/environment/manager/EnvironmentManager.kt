package de.rub.nds.sshstatelearner.environment.manager

/**
 * Abstracts the actual SML for the main class
 */
abstract class EnvironmentManager() {
    /**
     * Initialisation
     */
    abstract fun setUp()

    /**
     * This is where the actual SML should take place
     */
    abstract fun performLearning()

    /**
     * All dependencies should be terminated here so that a potential additional SML run can be started.
     */
    abstract fun setDown()

}