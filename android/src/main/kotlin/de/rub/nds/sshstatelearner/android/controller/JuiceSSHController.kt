package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.AppiumBy
import io.appium.java_client.appmanagement.ApplicationState
import org.openqa.selenium.support.ui.ExpectedConditions

/**
 * Automates the control of the JuiceSSH.
 */
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

    override fun setSettingsInApp() {
        //Nothing to do!
    }

    override fun connectToGetFingerprint() {
        fun acceptSSHFingerPrint() =
            waitUntilElementIsClickable(AppiumBy.id("android:id/button1")).click()

        restartAndConnectToServer()
        acceptSSHFingerPrint()
    }

    fun rejecttSSHFingerPrint() =
        waitUntilElementIsClickable(AppiumBy.id("android:id/button2")).click()

    /**
     * Determines the next action
     */
    private fun getAction(): Action? {
        val applicationIsNotRunning = driver.queryAppState(bundleId) == ApplicationState.NOT_RUNNING

        val alertIsShown = ExpectedConditions.elementToBeClickable(
            AppiumBy.id("android:id/aerr_close")
        ).apply(driver) != null

        val isNormalConnectPossible = ExpectedConditions.elementToBeClickable(
            AppiumBy.xpath(xPathToCickConnectButton)
        ).apply(driver) != null

        val isReconnectPossible = runCatching {
            ExpectedConditions.textToBePresentInElementLocated(
                AppiumBy.id("android:id/alertTitle"), "Connection Failed"
            ).apply(driver)
        }.getOrDefault(false)

        val isAcceptFingerPrintShown = runCatching {
            ExpectedConditions.textToBePresentInElementLocated(
                AppiumBy.id("android:id/alertTitle"), "Host Verification"
            ).apply(driver)
        }.getOrDefault(false)

        if (applicationIsNotRunning || alertIsShown) {
            return Action.RESTART
        } else if (isNormalConnectPossible && !isReconnectPossible) {
            return Action.NORMAL_CONNECT
        } else if (isReconnectPossible && !isNormalConnectPossible && !isAcceptFingerPrintShown) {
            return Action.RECONNECT
        } else if (isAcceptFingerPrintShown) {
            return Action.REFUSE
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

            Action.REFUSE -> {
                rejecttSSHFingerPrint()
                clickReconnectButton()
            }

            else -> {}
        }
    }


    private fun clickReconnectButton() = waitUntilElementIsClickable(
        AppiumBy.xpath(xPathToReconnectButton)
    ).click()

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