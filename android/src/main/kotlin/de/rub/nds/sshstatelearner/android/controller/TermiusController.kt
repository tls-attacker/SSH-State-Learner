package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.AppiumBy
import io.appium.java_client.appmanagement.ApplicationState
import org.openqa.selenium.Point
import org.openqa.selenium.support.ui.ExpectedConditions

/**
 * Automates the control of the Termius.
 */
class TermiusController(
    ipToAppium: String,
    portToAppium: Int,
    ipToServer: String,
    portToServer: Int,
    pathToApks: List<String>,
    udid: String
) : AndroidSSHClientController(ipToAppium, portToAppium, ipToServer, portToServer, pathToApks, udid) {
    override val bundleId = "com.server.auditor.ssh.client"
    val reconnectButtonId = "com.server.auditor.ssh.client:id/start_over_button"
    val connectButtonFooterXpath =
        "//android.widget.TextView[@resource-id=\"com.server.auditor.ssh.client:id/footer_text\"]"
    val connectButtonXPath =
        "(//android.view.ViewGroup[@resource-id=\"com.server.auditor.ssh.client:id/clickable_layout\"])[2]"

    override fun setSettingsInApp() {
        restartApp()
        finishTutorial()
        addHost()
    }

    private fun connectToServer() {
        waitUntilElementIsClickable(
            AppiumBy.xpath(connectButtonXPath)
        ).click()
    }

    private fun reconnectToServer() {
        waitUntilElementIsClickable(AppiumBy.id(reconnectButtonId)).click()
    }

    override fun connectToGetFingerprint() {
        fun clickSaveFingerprint() {
            waitUntilElementIsClickable(
                AppiumBy.id("com.server.auditor.ssh.client:id/save_and_continue_button")
            ).click()
        }

        connectToServer()
        clickSaveFingerprint()
        reconnectToServer()
    }

    private fun finishTutorial() {
        fun clickNext() =
            waitUntilElementIsClickable(AppiumBy.id("com.server.auditor.ssh.client:id/proceed_button")).click()

        fun skipVaultCreation() =
            waitUntilElementIsClickable(AppiumBy.id("com.server.auditor.ssh.client:id/skip_onboarding_button")).click()


        for (i in 0 until 4) {
            clickNext()
        }
        skipVaultCreation()
    }

    private fun addHost() {
        fun clickAddButton() =
            waitUntilElementIsClickable(AppiumBy.id("com.server.auditor.ssh.client:id/material_fab")).click()

        fun chooseCreateHost() =
            waitUntilElementIsClickable(AppiumBy.id("com.server.auditor.ssh.client:id/add_remote_host_action"))
                .click()

        fun hideKeyboard() {
            driver.hideKeyboard()
        }

        fun addAliasText() = waitUntilPresenceOfElementLocated(
            AppiumBy.id("com.server.auditor.ssh.client:id/alias_edit_text")
        ).sendKeys("SSH-STATE-LEARNER")

        fun addIpText() = waitUntilPresenceOfElementLocated(
            AppiumBy.id("com.server.auditor.ssh.client:id/host_edit_text")
        ).sendKeys(ipToServer)

        fun swipeDown() = swipe(Point(370, 731), Point(379, 427))

        fun addPortText() = waitUntilPresenceOfElementLocated(
            AppiumBy.id("com.server.auditor.ssh.client:id/ssh_port_edit_text")
        ).sendKeys("$portToServer")

        fun addUserText() = waitUntilPresenceOfElementLocated(
            AppiumBy.id("com.server.auditor.ssh.client:id/ssh_username_edit_text")
        ).sendKeys("attacker")

        fun saveHost() = waitUntilElementIsClickable(AppiumBy.id("com.server.auditor.ssh.client:id/save")).click()

        clickAddButton()
        chooseCreateHost()
        addAliasText()
        addIpText()
        hideKeyboard()
        swipeDown()
        addPortText()
        addUserText()
        saveHost()
    }

    /**
     * Determines the next action
     */
    private fun getAction(): Action? {
        val applicationIsNotRunning = driver.queryAppState(bundleId) == ApplicationState.NOT_RUNNING
        val alertIsShown = ExpectedConditions.elementToBeClickable(
            AppiumBy.id("android:id/aerr_close")
        ).apply(driver) != null

        val connectButtonFooter = ExpectedConditions.elementToBeClickable(
            AppiumBy.xpath(connectButtonFooterXpath)
        ).apply(driver)
        val isNormalConnectPossible = connectButtonFooter != null && "SSH, attacker" == connectButtonFooter.text

        val isReconnectPossible = ExpectedConditions.elementToBeClickable(
            AppiumBy.id(reconnectButtonId)
        ).apply(driver) != null

        if (applicationIsNotRunning || alertIsShown) {
            return Action.RESTART
        } else if (isNormalConnectPossible && !isReconnectPossible) {
            return Action.NORMAL_CONNECT
        } else if (isReconnectPossible && !isNormalConnectPossible) {
            return Action.RECONNECT
        } else {
            return null
        }
    }

    fun getActionAndExecuteIt() {
        val action = wait.until { getAction() }
        when (action) {
            Action.RESTART -> {
                restartApp()
                connectToServer()
            }

            Action.RECONNECT -> {
                reconnectToServer()
            }

            Action.NORMAL_CONNECT -> {
                connectToServer()
            }

            else -> {}
        }
    }

    override fun oneConnectForStateLearning() {
        catchAppiumException {
            getActionAndExecuteIt()
        }
    }
}