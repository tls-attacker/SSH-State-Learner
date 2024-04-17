package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.AppiumBy
import io.appium.java_client.appmanagement.ApplicationState
import org.openqa.selenium.Point
import org.openqa.selenium.StaleElementReferenceException
import org.openqa.selenium.TimeoutException
import org.openqa.selenium.support.ui.ExpectedConditions

class TermiusController(
    ipToAppium: String,
    portToAppium: Int,
    ipToServer: String,
    portToServer: Int,
    pathToApks: List<String>,
    udid: String
) : AndroidSSHClientController(ipToAppium, portToAppium, ipToServer, portToServer, pathToApks, udid) {
    override val bundleId = "com.server.auditor.ssh.client"

    override fun connectToGetFingerprint() {
        fun connectFirstTime() {
            waitUntilElementIsClickable(
                AppiumBy.xpath("(//android.view.ViewGroup[@resource-id=\"com.server.auditor.ssh.client:id/clickable_layout\"])[2]")
            ).click()
        }

        fun clickSaveFingerprint() {
            waitUntilElementIsClickable(
                AppiumBy.id("com.server.auditor.ssh.client:id/save_and_continue_button")
            ).click()
        }

        restartApp()
        finishTutorial()
        addHost()

        connectFirstTime()
        clickSaveFingerprint()
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

    override fun connectForStateLearning() {
        fun connectToServer() {
            waitUntilElementIsClickable(
                AppiumBy.xpath("(//android.view.ViewGroup[@resource-id=\"com.server.auditor.ssh.client:id/clickable_layout\"])[2]")
            ).click()
        }


        fun connectToServerIfAppIsRunningOrRestartApp(): Boolean? {
            /**
             * This approach is necessary because the app is unstable.
             */
            if (driver.queryAppState(bundleId) == ApplicationState.RUNNING_IN_FOREGROUND) {
                val element = wait.until {
                    val element =
                        ExpectedConditions.elementToBeClickable(AppiumBy.id("com.server.auditor.ssh.client:id/start_over_button"))
                            .apply(driver)
                    if (element != null) {
                        element
                    } else {
                        val element2 =
                            ExpectedConditions.elementToBeClickable(AppiumBy.xpath("//android.widget.TextView[@resource-id=\"com.server.auditor.ssh.client:id/footer_text\"]"))
                                .apply(driver)
                        if (element2 == null || "Active".equals(element2.text)) {
                            null
                        } else {
                            element2
                        }

                    }
                }
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
                restartApp()
                connectToServer()
                do {
                    connectToServerIfAppIsRunningOrRestartApp()
                } while (isInStateMachineLearningMode)
            } catch (_: StaleElementReferenceException) {
            } catch (_: TimeoutException) {
            }
        } while (isInStateMachineLearningMode)
    }
}