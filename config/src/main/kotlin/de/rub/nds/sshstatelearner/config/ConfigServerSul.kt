package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription

/**
 * Configuration class that contains special configuration attributes that are required for a server SUL.
 */
data class ConfigServerSul(
    @field:JsonPropertyDescription("Hostname of the system where the target SSH server is running")
    @field:JsonProperty(defaultValue = "localhost")
    var hostname: String = "localhost",

    @field:JsonPropertyDescription("Port on which the target SSH server is listening for incoming connection")
    @field:JsonProperty(defaultValue = "22")
    var port: Int = 22,
// Current not Implemented
//    @field:JsonPropertyDescription("Specifies how many SULs are used in parallel")
//    @field:JsonProperty(defaultValue = "1")
//    var countOfParallelSuls: Int = 1
) : ConfigSul()
