package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.AppiumBy
import io.appium.java_client.appmanagement.ApplicationState
import org.openqa.selenium.support.ui.ExpectedConditions

class JuiceSSHController(
    ipToAppium: String,
    portToAppium: Int,
    ipToServer: String,
    portToServer: Int,
    pathToApks: List<String>,
    udid: String
) : AndroidSSHClientController(ipToAppium, portToAppium, ipToServer, portToServer, pathToApks, udid) {
    override val bundleId = "com.sonelli.juicessh"
    private val xPathToCickConnectButton =
        "//android.widget.TextView[@resource-id=\"com.sonelli.juicessh:id/itemTitle\" and @text=\"Quick Connect\"]"
    private val xPathToReconnectButton = "//android.widget.Button[@resource-id=\"android:id/button1\"]"

    override fun connectToGetFingerprint() {
        fun acceptSSHFingerPrint() =
            waitUntilElementIsClickable(AppiumBy.id("android:id/button1")).click()

        restartAndConnectToServer()
        acceptSSHFingerPrint()
    }

    private fun getAction(): Action? {
        val applicationIsRunning = driver.queryAppState(bundleId) == ApplicationState.RUNNING_IN_FOREGROUND
        val alertIsShown = ExpectedConditions.elementToBeClickable(
            AppiumBy.id("android:id/aerr_close")
        ).apply(driver) != null
        val isNormalConnectPossible = ExpectedConditions.elementToBeClickable(
            AppiumBy.xpath(xPathToCickConnectButton)
        ).apply(driver) != null
        val isReconnectPossible = ExpectedConditions.elementToBeClickable(
            AppiumBy.xpath(xPathToReconnectButton)
        ).apply(driver) != null

        if (!applicationIsRunning || alertIsShown) {
            return Action.RESTART
        } else if (isNormalConnectPossible) {
            return Action.NORMAL_CONNECT
        } else if (isReconnectPossible) {
            return Action.RECONNECT
        } else {
            return null
        }
    }

    private fun getActionAndExecuteIt() {
        val action = wait.until { getAction() }
        when (action) {
            Action.RESTART -> {
                restartAndConnectToServer()
            }

            Action.RECONNECT -> {
                clickReconnectButton()
            }

            Action.NORMAL_CONNECT -> {
                connectToServer()
            }

            else -> {}
        }
    }


    private fun clickReconnectButton() = waitUntilElementIsClickable(
        AppiumBy.xpath(xPathToReconnectButton)
    ).click()

    override fun connectForStateLearning() {
        do {
            catchAppiumException {
                getActionAndExecuteIt()
            }
        } while (isInStateMachineLearningMode)
    }

    override fun oneConnectForStateLearning() {
        catchAppiumException { getActionAndExecuteIt() }
    }

    private fun connectToServer() {
        fun clickQuickConnectButton() = waitUntilElementIsClickable(
            AppiumBy.xpath(xPathToCickConnectButton)
        ).click()

        fun addServerInformation() = waitUntilPresenceOfElementLocated(
            AppiumBy.id("com.sonelli.juicessh:id/quickConnectHost")
        ).sendKeys("attacker@$ipToServer:$portToServer")

        fun clickConnectButton() = waitUntilElementIsClickable(AppiumBy.id("android:id/button1")).click()

        clickQuickConnectButton()
        addServerInformation()
        clickConnectButton()

    }

    private fun restartAndConnectToServer() {
        restartApp()
        connectToServer()
    }
}