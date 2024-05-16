package de.rub.nds.sshstatelearner.analysis.automata

import de.rub.nds.sshstatelearner.extraction.SshSymbol

abstract class AnalysisDFATransition(val inputSymbol: SshSymbol, val successorState: AnalysisDFAState) {

}