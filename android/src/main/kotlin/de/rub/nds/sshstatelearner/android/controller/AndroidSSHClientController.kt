package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.android.AndroidDriver
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.openqa.selenium.By
import org.openqa.selenium.NoSuchSessionException
import org.openqa.selenium.Point
import org.openqa.selenium.StaleElementReferenceException
import org.openqa.selenium.TimeoutException
import org.openqa.selenium.WebDriverException
import org.openqa.selenium.WebElement
import org.openqa.selenium.interactions.PointerInput
import org.openqa.selenium.remote.DesiredCapabilities
import org.openqa.selenium.support.ui.ExpectedConditions
import org.openqa.selenium.support.ui.WebDriverWait
import java.net.URI
import java.time.Duration

abstract class AndroidSSHClientController(
    protected val ipToAppium: String,
    protected val portToAppium: Int,
    protected val ipToServer: String,
    val portToServer: Int,
    protected val pathToApks: List<String>,
    udid: String
) {
    companion object {
        val logger: Logger = LogManager.getLogger()
    }
    protected abstract val bundleId: String
    private val caps: DesiredCapabilities = DesiredCapabilities().apply {
        setCapability("appium:udid", udid)
        setCapability("platformName", "Android")
        setCapability("appium:automationName", "UiAutomator2")
    }
    protected val driver: AndroidDriver by lazy {
        connectTo(ipToAppium, portToAppium)
    }

    protected val wait: WebDriverWait by lazy {
        WebDriverWait(driver, Duration.ofSeconds(10))
    }

    protected var isInStateMachineLearningMode = false

    fun installApp() {
        var appIsTerminated = false
        while (!appIsTerminated) {
            try {
                driver.terminateApp(bundleId)
                appIsTerminated = true
            } catch (e: WebDriverException) {
                logger.error(e)
            }
        }
        if (driver.isAppInstalled(bundleId)) {
            driver.terminateApp(bundleId)
            driver.executeScript("mobile:clearApp", mapOf("appId" to bundleId))
            Thread.sleep(Duration.ofSeconds(1))
            return
        }

        if (pathToApks.size == 1) {
            driver.installApp(pathToApks[0])

        } else {
            driver.executeScript(
                "mobile:installMultipleApks",
                mapOf("apks" to pathToApks, "options" to "r")
            )
            // Time for the installation.
            Thread.sleep(Duration.ofSeconds(10))
        }
    }

    abstract fun connectToGetFingerprint()

    abstract fun connectForStateLearning()

    abstract fun oneConnectForStateLearning()

    abstract fun init()

    private fun connectTo(ip: String, port: Int): AndroidDriver {
        return AndroidDriver(URI("http://$ip:$port/").toURL(), caps)
    }

    protected fun restartApp() {
        driver.terminateApp(bundleId)
        driver.activateApp(bundleId)
    }

    fun quit(): Unit = driver.quit()

    protected fun waitUntilElementIsClickable(by: By): WebElement =
        wait.until(
            ExpectedConditions.elementToBeClickable(by)
        )

    protected fun waitUntilPresenceOfElementLocated(by: By): WebElement =
        wait.until(
            ExpectedConditions.presenceOfElementLocated(by)
        )

    protected fun swipe(startPoint: Point, endPoint: Point) {
        val finger = PointerInput(PointerInput.Kind.TOUCH, "finger")
        val swipe = org.openqa.selenium.interactions.Sequence(finger, 1)
        swipe.addAction(
            finger.createPointerMove(
                Duration.ofMillis(0),
                PointerInput.Origin.viewport(), startPoint.getX(), startPoint.getY()
            )
        )
        swipe.addAction(finger.createPointerDown(PointerInput.MouseButton.LEFT.asArg()))
        swipe.addAction(
            finger.createPointerMove(
                Duration.ofMillis(1000),
                PointerInput.Origin.viewport(), endPoint.getX(), endPoint.getY()
            )
        )
        swipe.addAction(finger.createPointerUp(PointerInput.MouseButton.LEFT.asArg()))
        driver.perform(listOf(swipe))
    }

    protected fun catchAppiumException(func: () -> Unit) {
        var retry = true
        while (retry) {
            try {
                func()
                retry = false
            } catch (e: Exception) {
                when (e) {
                    is TimeoutException,
                    is NoSuchSessionException,
                    is StaleElementReferenceException -> {
                        logger.error(e)
                        restartApp()
                    }

                    else -> throw e
                }
            }
        }
    }

    protected enum class Action {
        RESTART, NORMAL_CONNECT, RECONNECT, REFUSE
    }
}