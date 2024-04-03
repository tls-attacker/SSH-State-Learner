package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.android.AndroidDriver
import org.openqa.selenium.By
import org.openqa.selenium.WebElement
import org.openqa.selenium.remote.DesiredCapabilities
import org.openqa.selenium.support.ui.ExpectedConditions
import org.openqa.selenium.support.ui.WebDriverWait
import java.net.URI
import java.time.Duration

abstract class AndroidSSHClientController(
    protected val ipToAppium: String,
    protected val portToAppium: Int,
    protected val ipToServer: String,
    protected val portToServer: Int,
    protected val pathToApks: List<String>,
    udid: String
) {
    protected abstract val bundleId: String
    private val caps: DesiredCapabilities = DesiredCapabilities().apply {
        setCapability("udid", udid)
        setCapability("platformName", "Android")
        setCapability("automationName", "UiAutomator2")
    }
    protected val driver = connectTo(ipToAppium, portToAppium)

    protected val wait = WebDriverWait(driver, Duration.ofMillis(5000))

    fun installApp() {
        if (driver.isAppInstalled(bundleId)) {
            return
        }

        if (pathToApks.size == 1) {
            driver.installApp("/home/jimba/apks/juicessh-v3.2.2_200.apk")

        } else {
            driver.executeScript(
                "mobile:installMultipleApks",
                mapOf("args" to pathToApks, "options" to "r")
            )
        }
    }

    abstract fun connectToGetFingerprint()

    abstract fun connectForStateLearning()

    private fun connectTo(ip: String, port: Int): AndroidDriver {
        return AndroidDriver(URI("http://$ip:$port").toURL(), caps)
    }

    protected fun restartApp() {
        driver.terminateApp(bundleId)
        driver.activateApp(bundleId)
    }

    fun webElement(by: By): WebElement =
        wait.until(
            ExpectedConditions.elementToBeClickable(by)
        )


}