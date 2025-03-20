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
 * An enumeration representing different equivalence oracle algorithms.
 */
enum class EquivalenceOracleType {
    /**
     * Performs an equivalence check by checking cached responses against the hypothesis.
     */
    CACHE_CONSISTENCY,

    /**
     * Performs an equivalence check by using a defined happy flow with message insertions.
     */
    HAPPY_FLOW,

    /**
     * Performs an equivalence check by complete, depth-bounded exploration.
     */
    COMPLETE_EXPLORATION,

    /**
     * Performs an equivalence check by testing a configurable amount of random words.
     */
    RANDOM_WORDS,

    /**
     * Performs an equivalence check by a random walk of configurable length and reset probability.
     */
    RANDOM_WALK,

    /**
     * Performs an equivalence check using the W-method.
     */
    W,

    /**
     * Performs an equivalence check using the randomized W-method.
     */
    RANDOM_W,

    /**
     * Performs an equivalence check using the Wp-method.
     */
    WP,

    /**
     * Performs an equivalence check using the randomized Wp-method.
     */
    RANDOM_WP;
}
