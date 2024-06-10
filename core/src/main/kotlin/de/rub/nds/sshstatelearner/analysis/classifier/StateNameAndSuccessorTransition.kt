package de.rub.nds.sshstatelearner.analysis.classifier

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import de.rub.nds.sshstatelearner.extraction.SshSymbol

data class StateNameAndSuccessorTransition(
    @JsonPropertyDescription("The name of the state")
    @JsonProperty(defaultValue = "")
    val stateName: String = "",
    @JsonPropertyDescription("The transition to the next state")
    @JsonProperty(defaultValue = "null")
    val successorTransition: SshSymbol? = null
)