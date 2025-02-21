package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import de.rub.nds.sshstatelearner.android.controller.constants.AndroidSshClientTyp

/**
 * Configuration class that contains special configuration attributes that are required for android client SUL.
 */
data class ConfigAndroidClientSul(
    @field:JsonPropertyDescription("Information for controlling the Android clients and the connection with the SUL")
    @field:JsonProperty(defaultValue = "[]")
    var androidConnectionInfos: List<AndroidConnectionInfo> = emptyList(),

    @field:JsonPropertyDescription("Which Android SSH client should be started.")
    @field:JsonProperty(defaultValue = "INVALID")
    var androidSshClientTyp: AndroidSshClientTyp = AndroidSshClientTyp.INVALID,

    @field:JsonPropertyDescription("Path to an APK or multiple APKs if an app has more than one")
    @field:JsonProperty(defaultValue = "[]")
    var pathToApks: List<String> = emptyList()
) : ConfigSul() {
    data class AndroidConnectionInfo(
        @field:JsonPropertyDescription("IP to connect to the SUL")
        @field:JsonProperty(defaultValue = "")
        var ipToServer: String = "",
        @field:JsonPropertyDescription("Port to connect to the SUL")
        @field:JsonProperty(defaultValue = "-1")
        var portToServer: Int = -1,
        @field:JsonPropertyDescription("IP to connect to Appium")
        @field:JsonProperty(defaultValue = "")
        var ipToAppium: String = "",
        @field:JsonPropertyDescription("Port to connect to Appium")
        @field:JsonProperty(defaultValue = "-1")
        var portToAppium: Int = -1,
        @field:JsonPropertyDescription("UDID of the device to be tested. Could be retrieved from adb devices -l output.")
        @field:JsonProperty(defaultValue = "")
        var uuid: String = ""
    )
}