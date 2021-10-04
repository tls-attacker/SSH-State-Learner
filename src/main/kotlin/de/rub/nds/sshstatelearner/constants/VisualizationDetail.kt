/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.constants

enum class VisualizationDetail {
    /**
     * The most abstract level of detail for visualization. Offers every feature from the medium branch as well as:
     *  - Removal of circular edges without output
     *  - Shorter labels for transitioning edges
     */
    SHORT,

    /**
     * A medium level of detail for visualization. Offers the following features:
     *  - Combination of edges (If there is more than one transitioning edge between two states, only a single edge
     *    is being outputted to the resulting transition graph)
     */
    MEDIUM,

    /**
     * The most detailed level of visualization. Outputs every state and transition without further modification.
     */
    LONG
}
