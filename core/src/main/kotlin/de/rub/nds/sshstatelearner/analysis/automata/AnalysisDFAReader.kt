package de.rub.nds.sshstatelearner.analysis.automata

import com.fasterxml.jackson.core.JsonParser.Feature
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File

class AnalysisDFAReader {
    fun readJson(pathToFile: String): AnalysisDFACreationHelper =
        ObjectMapper().enable(Feature.INCLUDE_SOURCE_IN_LOCATION)
            .readValue(File(pathToFile), AnalysisDFACreationHelper::class.java)

}