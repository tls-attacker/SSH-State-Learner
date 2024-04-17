package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.AppiumBy
import io.appium.java_client.appmanagement.ApplicationState
import org.openqa.selenium.Point
import org.openqa.selenium.StaleElementReferenceException
import org.openqa.selenium.TimeoutException
import org.openqa.selenium.support.ui.ExpectedConditions


class ConnectBotController(
    ipToAppium: String,
    portToAppium: Int,
    ipToServer: String,
    portToServer: Int,
    pathToApks: List<String>,
    udid: String
) : AndroidSSHClientController(ipToAppium, portToAppium, ipToServer, portToServer, pathToApks, udid) {
    override val bundleId = "org.connectbot"

    override fun connectToGetFingerprint() {
        fun acceptSSHFingerPrint() = waitUntilElementIsClickable(
            AppiumBy.id("org.connectbot:id/console_prompt_yes")
        ).click()

        addHost()
        setSettings()
        connectToServer()
        acceptSSHFingerPrint()
    }

    override fun connectForStateLearning() {
        fun connectToServerIfAppIsRunningOrRestartApp(): Boolean? {
            /**
             * This approach is necessary because the app is very unstable.
             */
            if (driver.queryAppState(bundleId) == ApplicationState.RUNNING_IN_FOREGROUND) {
                val element =
                    ExpectedConditions.elementToBeClickable(
                        AppiumBy.xpath("//android.widget.RelativeLayout[@resource-id=\"android:id/content\"]")
                    ).apply(driver)
                if (element != null) {
                    element.click()
                    return true
                }
            } else {
                restartApp()
            }
            return null
        }

        do {
            try {
                connectToServer()

                do {
                    wait.until { _ ->
                        connectToServerIfAppIsRunningOrRestartApp()
                    }
                } while (isInStateMachineLearningMode)
            } catch (_: StaleElementReferenceException) {
            } catch (_: TimeoutException) {
            }
        } while (isInStateMachineLearningMode)
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

    private fun connectToServer() {
        fun clickToConnectToServer() = waitUntilElementIsClickable(
            AppiumBy.xpath("//android.widget.RelativeLayout[@resource-id=\"android:id/content\"]")
        ).click()

        restartApp()
        clickToConnectToServer()
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