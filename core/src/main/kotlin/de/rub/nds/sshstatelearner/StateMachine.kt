/*
 * SSH State Learner - A tool for extracting state machines from SSH server implementations
 *
 * Copyright 2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.sshstatelearner

import de.rub.nds.sshstatelearner.analysis.data.GraphDetails
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import net.automatalib.automaton.graph.TransitionEdge
import net.automatalib.automaton.transducer.MealyMachine
import net.automatalib.serialization.dot.DOTVisualizationHelper
import net.automatalib.serialization.dot.GraphDOT
import net.automatalib.alphabet.Alphabet
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.io.StringWriter
import java.io.Writer

abstract class StateMachine<S, I, T, O>(
    var mealyMachine: MealyMachine<S, I, T, O>,
    var alphabet: Alphabet<I>
) {

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    abstract var graphDetails: GraphDetails<S, I, T>

    abstract fun analyzeMealyMachine()

    protected abstract fun getVisualizationHelper(detail: VisualizationDetail): DOTVisualizationHelper<S, TransitionEdge<I, T>>

    fun exportToDotAndPDF(graphFile: File, detail: VisualizationDetail) {
        exportToDot(graphFile, detail)
        try {
            var fileName = graphFile.absolutePath
            fileName = fileName.substring(0, fileName.length - 4)
            Runtime.getRuntime().exec("dot -Tpdf ${graphFile.absolutePath} -o $fileName.pdf")
        } catch (e: IOException) {
            LOGGER.warn("Caught an IOException while converting dot to pdf", e)
        }
    }

    fun exportToDot(graphFile: File, detail: VisualizationDetail) {
        try {
            graphFile.createNewFile()
            exportToDot(FileWriter(graphFile), detail)
        } catch (e: IOException) {
            LOGGER.warn("Caught an IOException while exporting mealy machine to DOT file", e)
        }
    }

    fun exportToDot(writer: Writer, detail: VisualizationDetail) {
        GraphDOT.write(
            mealyMachine.transitionGraphView(alphabet),
            writer,
            getVisualizationHelper(detail)
        )
        writer.close()
    }

    fun toString(detail: VisualizationDetail): String {
        val sw = StringWriter()
        exportToDot(sw, detail)
        return sw.toString()
    }
}
