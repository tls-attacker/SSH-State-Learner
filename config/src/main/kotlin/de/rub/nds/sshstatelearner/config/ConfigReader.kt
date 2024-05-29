package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.core.JsonParser.Feature
import com.fasterxml.jackson.databind.ObjectMapper
import java.io.File

class ConfigReader {
    fun readConfig(pathToFile: String): ConfigGeneral = try {
        ObjectMapper().enable(Feature.INCLUDE_SOURCE_IN_LOCATION)
            .readValue(File(pathToFile), ConfigGeneral::class.java)
    } catch (error: Exception) {
        throw ConfigReadException("Error reading config file", error)
    }
}