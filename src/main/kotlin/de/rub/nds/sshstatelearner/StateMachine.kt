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
import java.io.File
import java.io.FileWriter
import java.io.IOException
import java.io.StringWriter
import java.io.Writer
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.words.Alphabet
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger

abstract class StateMachine<S, I, T, O>(
    var mealyMachine: MealyMachine<S, I, T, O>,
    var alphabet: Alphabet<I>
) {

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    abstract fun exportToDotAndPDF(graphFile: File, detail: VisualizationDetail)

    fun exportToDotAndPDF(graphFile: File, detail: VisualizationDetail, graphDetails: GraphDetails<S, I, T>) {
        try {
            graphFile.createNewFile()
            exportToDot(FileWriter(graphFile), detail, graphDetails)
            var fileName = graphFile.absolutePath
            fileName = fileName.substring(0, fileName.length - 4)
            Runtime.getRuntime().exec("dot -Tpdf ${graphFile.absolutePath} -o $fileName.pdf")
        } catch (e: IOException) {
            LOGGER.warn("Caught an IOException while exporting mealy machine to DOT file and converting to pdf", e)
        }
    }

    abstract fun exportToDot(writer: Writer, detail: VisualizationDetail)

    abstract fun exportToDot(writer: Writer, detail: VisualizationDetail, graphDetails: GraphDetails<S, I, T>)

    fun toString(detail: VisualizationDetail): String {
        val sw = StringWriter()
        exportToDot(sw, detail)
        return sw.toString()
    }
}
