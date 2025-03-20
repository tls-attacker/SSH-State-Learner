/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner.analysis.classifier

import de.rub.nds.sshstatelearner.StateMachine
import net.automatalib.word.Word
import java.util.LinkedList
import java.util.Queue
import kotlin.collections.HashMap

abstract class Classifier<S, I, T, O> {

    // TODO: Add return type when classifiers are able to detect vulnerabilities
    abstract fun performClassification(stateMachine: StateMachine<S, I, T, O>)

    protected fun getPathToState(stateMachine: StateMachine<S, I, T, O>, destState: S): Word<I>? {
        val initialState = stateMachine.mealyMachine.initialState
        return if (initialState == null) null else getPathToState(stateMachine, initialState, destState)
    }

    protected fun getPathToState(stateMachine: StateMachine<S, I, T, O>, sourceState: S, destState: S): Word<I>? {
        val wordMap = HashMap<S, Word<I>>()
        val queue: Queue<S> = LinkedList()

        wordMap[sourceState] = Word.epsilon()
        queue.add(sourceState)

        // Perform BFS while keeping track of how to reach each state
        while (!queue.isEmpty()) {
            val currState = queue.remove()
            for (symbol in stateMachine.alphabet) {
                val nextState = stateMachine.mealyMachine.getSuccessor(currState, symbol)
                // Check if we haven't recorded a valid word on how to reach the state yet
                if (!wordMap.containsKey(nextState) && nextState != null) {
                    wordMap[nextState] = wordMap[currState]!!.append(symbol)
                    queue.add(nextState)
                }
            }
        }

        // Check if destState is reachable from sourceState
        return if (wordMap[destState] != null) wordMap[destState] else null
    }
}
