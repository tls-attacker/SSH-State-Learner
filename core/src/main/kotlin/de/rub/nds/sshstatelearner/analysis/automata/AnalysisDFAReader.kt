package de.rub.nds.sshstatelearner.analysis.automata

import com.fasterxml.jackson.core.JsonParser.Feature
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File

/**
 * Helper class for reading and writing AnalysisDFACreationHelper as JSON
 */
class AnalysisDFAReader {
    fun readJson(pathToFile: String): AnalysisDFACreationHelper =
        ObjectMapper().enable(Feature.INCLUDE_SOURCE_IN_LOCATION)
            .readValue(File(pathToFile), AnalysisDFACreationHelper::class.java)

    fun writeJson(pathToFile: String, analysisDFACreationHelper: AnalysisDFACreationHelper): Unit =
        ObjectMapper().enable(Feature.INCLUDE_SOURCE_IN_LOCATION)
            .writeValue(File(pathToFile), analysisDFACreationHelper)


}