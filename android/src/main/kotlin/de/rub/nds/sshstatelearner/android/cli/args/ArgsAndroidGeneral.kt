package de.rub.nds.sshstatelearner.android.cli.args

import com.beust.jcommander.Parameter
import de.rub.nds.sshstatelearner.android.controller.constants.AndroidSshClientTyp

/**
 * CLI options to control Android SSH clients without state learning.
 */
object ArgsAndroidGeneral {
    @Parameter(names = ["--help"], help = true, description = "Print this help screen", order = 0)
    var help = false
        private set

    @Parameter(
        names = ["--android-ssh-client-typ"],
        required = true,
        description = "Which Android SSH client should be started. You can choose between JUICE_SSH, CONNECT_BOT and TERMIUS",
        order = 1
    )
    var androidSshClientTyp = AndroidSshClientTyp.INVALID
        private set

    @Parameter(
        names = ["--path-to-apks"],
        required = true,
        description = "Path to an APK or multiple APKs if an app has more than one",
        variableArity = true,
        order = 2
    )
    var pathToApks: List<String> = listOf()
        private set

    @Parameter(
        names = ["--ip-to-appium"],
        description = "IP to the appium server",
        order = 3
    )
    var ipToAppium = "127.0.0.1"
        private set

    @Parameter(
        names = ["--port-to-appium"],
        description = "Port to the appium server",
        order = 4
    )
    var portToAppium = 4723
        private set

    @Parameter(
        names = ["--ip-to-ssh-server"],
        description = "IP to the ssh server",
        order = 5
    )
    var ipToSshServer = "10.0.2.2"
        private set

    @Parameter(
        names = ["--port-to-ssh-server"],
        description = "Port to the ssh server",
        order = 6
    )
    var portToSshServer = 48223
        private set

    @Parameter(
        names = ["--udid"],
        description = "UDID of the Android device. See in Android SDK platform tools with the command \"adb devices\" ",
        order = 6
    )
    var udid = "emulator-5554"
        private set
}