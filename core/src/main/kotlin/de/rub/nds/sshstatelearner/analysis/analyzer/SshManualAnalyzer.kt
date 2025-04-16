package de.rub.nds.sshstatelearner.analysis.analyzer

import de.rub.nds.sshstatelearner.analysis.classifier.CommonClassifier
import de.rub.nds.sshstatelearner.analysis.classifier.ManuallyClassifier
import de.rub.nds.sshstatelearner.analysis.classifier.StateNameAndSuccessorTransition
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint

class SshManualAnalyzer<S, T>(private val stateNameAndSuccessorTransitions: List<StateNameAndSuccessorTransition>) :
    Analyzer<S, SshSymbol, T, ResponseFingerprint>() {
    init {
        classifiers.add(CommonClassifier())
        classifiers.add(ManuallyClassifier(stateNameAndSuccessorTransitions))
    }
}