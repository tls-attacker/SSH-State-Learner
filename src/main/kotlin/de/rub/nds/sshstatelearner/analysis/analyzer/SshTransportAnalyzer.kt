package de.rub.nds.sshstatelearner.analysis.analyzer

import de.rub.nds.sshstatelearner.analysis.data.SshTransportGraphDetails
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class SshTransportAnalyzer<S, T>(graphDetails: SshTransportGraphDetails<S, T>) : Analyzer<S, SshSymbol, T, ResponseFingerprint>(graphDetails) {

    init {
        TODO("Register SSH transport classifiers")
    }

    override val graphDetails: SshTransportGraphDetails<S, T>
        get() = super.graphDetails as SshTransportGraphDetails<S, T>
}