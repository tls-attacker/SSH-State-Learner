/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.data

import net.automatalib.words.Word

abstract class GraphDetails<S, I, T> {
    var initialState: S? = null
    var errorState: S? = null
    var happyFlows: MutableList<Word<S>> = mutableListOf()
    var happyFlowTransitions: MutableSet<T> = mutableSetOf()

    abstract fun extractStateNames(): Map<S, String>
}
