/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.learner

/**
 * An enumeration representing different output formats of automaton hypothesis.
 */
enum class OutputFormat {
    /**
     * A serialized output of a hypothesis using the GraphDOT serialization format.
     */
    SERIALIZED,

    /**
     * A simple visualization of a hypothesis using the build-in visualization of AutomataLib.
     */
    SIMPLE_VISUALIZATION;
}
