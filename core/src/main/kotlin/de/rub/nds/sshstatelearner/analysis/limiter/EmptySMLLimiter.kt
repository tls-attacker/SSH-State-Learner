package de.rub.nds.sshstatelearner.analysis.limiter

class EmptySMLLimiter : SMLLimiter() {
    override fun init() {
        //Empty
    }

    override fun createSMLRun(): SMLRun = EmptySMLRun()
}