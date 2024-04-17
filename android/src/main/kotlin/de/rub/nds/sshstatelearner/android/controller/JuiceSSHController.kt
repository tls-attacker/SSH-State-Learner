package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.AppiumBy
import org.openqa.selenium.StaleElementReferenceException
import org.openqa.selenium.TimeoutException

class JuiceSSHController(
    ipToAppium: String,
    portToAppium: Int,
    ipToServer: String,
    portToServer: Int,
    pathToApks: List<String>,
    udid: String
) : AndroidSSHClientController(ipToAppium, portToAppium, ipToServer, portToServer, pathToApks, udid) {
    override val bundleId = "com.sonelli.juicessh"

    override fun connectToGetFingerprint() {
        fun acceptSSHFingerPrint() =
            waitUntilElementIsClickable(AppiumBy.id("android:id/button1")).click()

        connectToServer()
        acceptSSHFingerPrint()
    }


    override fun connectForStateLearning() {
        fun clickReconnectButton() = waitUntilElementIsClickable(
            AppiumBy.xpath("//android.widget.Button[@resource-id=\"android:id/button1\"]")
        ).click()

        fun reconnectToServerIfPossibleOrBreak(): Boolean {
            val message = waitUntilPresenceOfElementLocated(AppiumBy.id("android:id/message"))

            if (!message.text.contains("Do you want to retry?")) {
                return false
            } else {
                clickReconnectButton()
                return true
            }
        }

        do {
            try {
                connectToServer()

                do {
                    val reconnectWasSuccessful = reconnectToServerIfPossibleOrBreak()
                    if (!reconnectWasSuccessful) {
                        break
                    }
                } while (isInStateMachineLearningMode)
            } catch (_: StaleElementReferenceException) {
            } catch (_: TimeoutException) {
            }
        } while (isInStateMachineLearningMode)
    }

    private fun connectToServer() {
        fun clickQuickConnectButton() = waitUntilElementIsClickable(
            AppiumBy.xpath("//android.widget.TextView[@resource-id=\"com.sonelli.juicessh:id/itemTitle\" and @text=\"Quick Connect\"]")
        ).click()

        fun addServerInformation() = waitUntilPresenceOfElementLocated(
            AppiumBy.id("com.sonelli.juicessh:id/quickConnectHost")
        ).sendKeys("attacker@$ipToServer:$portToServer")

        fun clickConnectButton() = waitUntilElementIsClickable(AppiumBy.id("android:id/button1")).click()

        restartApp()
        clickQuickConnectButton()
        addServerInformation()
        clickConnectButton()
    }
}