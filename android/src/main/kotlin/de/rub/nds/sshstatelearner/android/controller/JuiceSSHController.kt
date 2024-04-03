package de.rub.nds.sshstatelearner.android.controller

import io.appium.java_client.AppiumBy
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

    override fun connectToGetFingerprint() {
        restartApp()

        val toClick = wait.until(
            ExpectedConditions.elementToBeClickable(AppiumBy.xpath("//android.widget.TextView[@resource-id=\"com.sonelli.juicessh:id/itemTitle\" and @text=\"Manage Connections\"]"))
        )
        toClick.click()

        val toClick2 = wait.until(
            ExpectedConditions.elementToBeClickable(AppiumBy.xpath("//android.widget.ExpandableListView[@resource-id=\"com.sonelli.juicessh:id/expandable_list\"]/android.widget.RelativeLayout[2]"))
        )
        toClick2.click()

        while (true) {
            val toClick3 = wait.until(
                ExpectedConditions.elementToBeClickable(AppiumBy.xpath("//android.widget.Button[@resource-id=\"android:id/button1\"]"))
            )
            toClick3.click()
        }


    }

    override fun connectForStateLearning() {
        TODO("Not yet implemented")
    }
}