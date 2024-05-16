package de.rub.nds.sshstatelearner.analysis.limiter

abstract class SMLLimiter {
    abstract fun init()

    abstract fun createSMLRun(): SMLRun
}