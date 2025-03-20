/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.constants

/**
 * An enumeration representing different active automaton learning algorithms.
 */
enum class LearningAlgorithmType {
    /**
     * Direct hypothesis construction
     */
    DHC,

    /**
     * Kearns Vazirani
     */
    KV,

    /**
     * The (extensible) L* algorithm
     */
    LSTAR,

    /**
     * The TTT algorithm
     */
    TTT;
}
