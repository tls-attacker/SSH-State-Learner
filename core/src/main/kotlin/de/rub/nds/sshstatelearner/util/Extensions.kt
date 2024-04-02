/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.util

/**
 * Returns all possible combinations with the specified length
 *
 * @param length Length of the combinations
 * @return A list containing all possible combinations
 */
fun <T> Iterable<T>.combinations(length: Int): List<List<T>> {
    var combinations = this.map { listOf(it) }
    for (i in 1 until length) {
        combinations = combinations.flatMap { prefix ->
            this.map { element ->
                prefix + element
            }
        }
    }
    return combinations
}
