package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import de.rub.nds.sshstatelearner.android.controller.constants.AndroidSshClientTyp

data class ConfigAndroidClientSul(
    @field:JsonPropertyDescription("Information for controlling the Android clients and the connection with the SUL")
    @field:JsonProperty(defaultValue = "[]")
    var androidConnectionInfos: List<AndroidConnectionInfo> = emptyList(),

    @field:JsonPropertyDescription("Which Android SSH client should be started.")
    @field:JsonProperty(defaultValue = "INVALID")
    var androidSshClientTyp: AndroidSshClientTyp = AndroidSshClientTyp.INVALID
) : ConfigSul() {
    data class AndroidConnectionInfo(
        @field:JsonPropertyDescription("IP to connect to the SUL")
        var ipToServer: String = "",
        @field:JsonPropertyDescription("Port to connect to the SUL")
        var portToServer: Int = -1,
        @field:JsonPropertyDescription("IP to connect to Appium")
        var ipToAppium: String = "",
        @field:JsonPropertyDescription("Port to connect to Appium")
        var portToAppium: Int = -1,
        @field:JsonPropertyDescription("Path to an APK or multiple APKs if an app has more than one")
        var pathToApks: List<String> = emptyList(),
        @field:JsonPropertyDescription("UDID of the device to be tested. Could be retrieved from adb devices -l output.")
        var uuid: String = ""
    )
}