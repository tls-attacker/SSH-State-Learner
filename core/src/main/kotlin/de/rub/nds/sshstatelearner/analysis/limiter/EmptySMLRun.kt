package de.rub.nds.sshstatelearner.analysis.limiter

import de.rub.nds.sshstatelearner.extraction.SshSymbol

class EmptySMLRun : SMLRun() {
    override fun step(inputSymbol: SshSymbol?): Boolean {
        return true
    }

    override fun saveState() {
        //Empty
    }

    override fun restoreState() {
        //Empty
    }
}