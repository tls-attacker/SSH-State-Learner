package de.rub.nds.sshstatelearner.analysis.limiter

import de.rub.nds.sshstatelearner.extraction.SshSymbol

abstract class SMLRun {

    abstract fun step(inputSymbol: SshSymbol?): Boolean

    abstract fun saveState()

    abstract fun restoreState()
}