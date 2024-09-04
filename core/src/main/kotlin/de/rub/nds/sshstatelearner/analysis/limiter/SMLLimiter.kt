package de.rub.nds.sshstatelearner.analysis.limiter

/*
 * Abstract class for additional SMLLimiter types
 */
abstract class SMLLimiter {
    abstract fun init()

    abstract fun createSMLRun(): SMLRun
}