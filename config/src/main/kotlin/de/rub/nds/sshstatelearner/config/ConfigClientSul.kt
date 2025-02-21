package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription

/**
 * Configuration class that contains special configuration attributes that are required for a client SUL.
 */
data class ConfigClientSul(
    @field:JsonPropertyDescription("Information for clients to connect to the SUL")
    @field:JsonProperty(defaultValue = "[]")
    var connectionInfos: List<ConnectionInfo> = emptyList()
) : ConfigSul() {
    data class ConnectionInfo(
        @field:JsonPropertyDescription("IP to connect to the SUL")
        var ipToServer: String = "",
        @field:JsonPropertyDescription("Port to connect to the SUL")
        var portToServer: Int = -1
    )
}