package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.AppiumBy
import io.appium.java_client.appmanagement.ApplicationState
import org.openqa.selenium.Point
import org.openqa.selenium.support.ui.ExpectedConditions

/**
 * Automates the control of the ConnectBot.
 */
class ConnectBotController(
    ipToAppium: String,
    portToAppium: Int,
    ipToServer: String,
    portToServer: Int,
    pathToApks: List<String>,
    udid: String
) : AndroidSSHClientController(ipToAppium, portToAppium, ipToServer, portToServer, pathToApks, udid) {
    override val bundleId = "org.connectbot"
    private val xpathToConnectButton = "//android.widget.RelativeLayout[@resource-id=\"android:id/content\"]"

    override fun setSettingsInApp() {
        addHost()
        setSettings()
    }

    override fun connectToGetFingerprint() {
        fun acceptSSHFingerPrint() = waitUntilElementIsClickable(
            AppiumBy.id("org.connectbot:id/console_prompt_yes")
        ).click()

        restartAndconnectToServer()
        acceptSSHFingerPrint()
    }

    private fun clickConnectToServerButton() {
        waitUntilElementIsClickable(AppiumBy.xpath(xpathToConnectButton)).click()
    }

    private fun rejectSSHFingerPrint() {
        waitUntilElementIsClickable(AppiumBy.id("org.connectbot:id/console_prompt_no")).click()
    }

    /**
     * Determines the next action
     */
    private fun getNextAction(): Action? {
        val applicationIsNotRunning = driver.queryAppState(bundleId) == ApplicationState.NOT_RUNNING

        val alertIsShown = ExpectedConditions.elementToBeClickable(
            AppiumBy.id("android:id/aerr_close")
        ).apply(driver) != null

        val isNormalConnectPossible = ExpectedConditions.elementToBeClickable(
            AppiumBy.xpath(xpathToConnectButton)
        ).apply(driver) != null

        val isAcceptFingerPrintShown = runCatching {
            ExpectedConditions.textToBePresentInElementLocated(
                AppiumBy.id("org.connectbot:id/console_prompt"), "Are you sure you want\nto continue connecting?"
            ).apply(driver)
        }.getOrDefault(false)



        if (applicationIsNotRunning || alertIsShown) {
            return Action.RESTART
        } else if (isNormalConnectPossible) {
            return Action.NORMAL_CONNECT
        } else if (isAcceptFingerPrintShown) {
            return Action.REFUSE
        } else {
            return null
        }
    }

    private fun getNextActionAndExecuteIt() {
        val action = wait.until({ _ -> getNextAction() })
        if (Action.RESTART == action) {
            restartApp()
            clickConnectToServerButton()
        } else if (Action.NORMAL_CONNECT == action) {
            clickConnectToServerButton()
        } else if (Action.REFUSE == action) {
            rejectSSHFingerPrint()
            clickConnectToServerButton()
        } else {
            throw IllegalStateException()
        }
    }


    override fun oneConnectForStateLearning() {
        catchAppiumException {
            getNextActionAndExecuteIt()
        }
    }

    private fun addHost() {
        fun clickAddHost() = waitUntilElementIsClickable(
            AppiumBy.accessibilityId("Add host")
        ).click()

        fun addServerInformation() = waitUntilPresenceOfElementLocated(
            AppiumBy.id("org.connectbot:id/quickconnect_field")
        ).sendKeys("attacker@$ipToServer:$portToServer")

        fun swipeToOptionCloseOnDisconnect() = swipe(Point(346, 1180), Point(337, 50))

        fun activateOptionCloseOnDisconnect() = waitUntilElementIsClickable(
            AppiumBy.id("org.connectbot:id/close_on_disconnect_item")
        ).click()

        fun finishAddHost() = waitUntilElementIsClickable(AppiumBy.accessibilityId("Add host")).click()

        restartApp()
        clickAddHost()
        addServerInformation()
        swipeToOptionCloseOnDisconnect()
        activateOptionCloseOnDisconnect()
        finishAddHost()
    }

    private fun restartAndconnectToServer() {
        restartApp()
        clickConnectToServerButton()
    }

    private fun setSettings() {
        fun clickMoreOption() = waitUntilElementIsClickable(AppiumBy.accessibilityId("More options")).click()

        fun clickSetting() = waitUntilElementIsClickable(
            AppiumBy.xpath("(//android.widget.LinearLayout[@resource-id=\"org.connectbot:id/content\"])[5]")
        ).click()

        fun swipeToSettingsOption() = swipe(Point(329, 1036), Point(341, 694))

        fun selectRotationMode() = waitUntilElementIsClickable(
            AppiumBy.xpath("//androidx.recyclerview.widget.RecyclerView[@resource-id=\"org.connectbot:id/recycler_view\"]/android.widget.LinearLayout[8]/android.widget.RelativeLayout")
        ).click()

        fun chooseForcePortrait() = waitUntilElementIsClickable(
            AppiumBy.xpath("//android.widget.CheckedTextView[@resource-id=\"android:id/text1\" and @text=\"Force portrait\"]")
        ).click()

        fun returnToHome() = waitUntilElementIsClickable(AppiumBy.accessibilityId("Navigate up")).click()

        clickMoreOption()
        clickSetting()
        swipeToSettingsOption()
        selectRotationMode()
        chooseForcePortrait()
        returnToHome()
    }


}