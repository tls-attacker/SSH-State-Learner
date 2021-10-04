package de.rub.nds.sshstatelearner.analysis.analyzer

import de.rub.nds.sshstatelearner.analysis.classifier.CommonClassifier
import de.rub.nds.sshstatelearner.analysis.classifier.ConnectionHappyFlowClassifier
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class SshConnectionAnalyzer<S, T> : Analyzer<S, SshSymbol, T, ResponseFingerprint>() {

    init {
        classifiers.add(CommonClassifier())
        classifiers.add(ConnectionHappyFlowClassifier())
    }
}