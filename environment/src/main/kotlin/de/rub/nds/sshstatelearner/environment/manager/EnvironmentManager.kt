package de.rub.nds.sshstatelearner.environment.manager

abstract class EnvironmentManager() {
    abstract fun setUp()

    abstract fun performLearning()

    abstract fun setDown()

}