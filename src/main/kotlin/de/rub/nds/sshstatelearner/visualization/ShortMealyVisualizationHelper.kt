/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.visualization

import de.rub.nds.sshstatelearner.analysis.data.GraphDetails
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import net.automatalib.automata.transducers.TransitionOutputAutomaton
import net.automatalib.automata.visualization.AutomatonVisualizationHelper

class ShortMealyVisualizationHelper<S, I, T, O>(
    automaton: TransitionOutputAutomaton<S, I, T, O>,
    private val graphDetails: GraphDetails<S, I, T>,
    private val detail: VisualizationDetail
) : AutomatonVisualizationHelper<S, I, T, TransitionOutputAutomaton<S, I, T, O>>(automaton) {

    constructor(
        automaton: TransitionOutputAutomaton<S, I, T, O>,
        graphDetails: GraphDetails<S, I, T>
    ) : this(automaton, graphDetails, VisualizationDetail.LONG)
}
