package de.rub.nds.sshstatelearner.analysis.limiter

import de.rub.nds.sshstatelearner.analysis.automata.AnalysisDFACreationHelper
import de.rub.nds.sshstatelearner.analysis.automata.AnalysisDFARun
import de.rub.nds.sshstatelearner.extraction.SshSymbol

class DFASMLLimiter {
    private val analysisDFACreationHelper: AnalysisDFACreationHelper by lazy { init() }

    fun init(): AnalysisDFACreationHelper {
        val analysisDFACreationHelper = AnalysisDFACreationHelper(
            setOf(
                SshSymbol.MSG_KEXINIT,
                SshSymbol.MSG_KEX_ECDH_REPLY,
                SshSymbol.MSG_NEWKEYS,
                SshSymbol.MSG_SERVICE_ACCEPT
            ),
            setOf(
                SshSymbol.MSG_USERAUTH_FAILURE,
                SshSymbol.MSG_USERAUTH_SUCCESS,
                SshSymbol.MSG_USERAUTH_BANNER,
                SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_INVALID,
                SshSymbol.MSG_USERAUTH_REQUEST_PASSWD_VALID
            )
        )
        //Happy FLow
        val protocolVersionExchanged = analysisDFACreationHelper.createState()
        val kexAlgorithmsNegotiatedState = analysisDFACreationHelper.createState()

        analysisDFACreationHelper.createTransitionBetween(
            protocolVersionExchanged,
            kexAlgorithmsNegotiatedState,
            SshSymbol.MSG_KEXINIT
        )

        analysisDFACreationHelper.createSelfTransition(kexAlgorithmsNegotiatedState, SshSymbol.MSG_KEXINIT)

        val keysDerived = analysisDFACreationHelper.createState()
        analysisDFACreationHelper.createTransitionBetween(
            kexAlgorithmsNegotiatedState,
            keysDerived,
            SshSymbol.MSG_KEX_ECDH_REPLY
        )
        analysisDFACreationHelper.createSelfTransition(keysDerived, SshSymbol.MSG_KEXINIT)

        val encryptionEnabled = analysisDFACreationHelper.createState()
        analysisDFACreationHelper.createTransitionBetween(keysDerived, encryptionEnabled, SshSymbol.MSG_NEWKEYS)

        val protocolFinished = analysisDFACreationHelper.createState()
        analysisDFACreationHelper.createTransitionBetween(
            encryptionEnabled,
            protocolFinished,
            SshSymbol.MSG_SERVICE_ACCEPT
        )
        //analysisDFA.changeStateToAcceptAllInputSymbols(protocolFinished)

        //alternativeWay
        val firstState = analysisDFACreationHelper.createState()
        analysisDFACreationHelper.createTransitionBetween(
            kexAlgorithmsNegotiatedState,
            firstState,
            SshSymbol.MSG_SERVICE_ACCEPT
        )
        listOf(SshSymbol.MSG_KEXINIT, SshSymbol.MSG_SERVICE_ACCEPT).forEach {
            analysisDFACreationHelper.createSelfTransition(firstState, it)
        }

        val secondState = analysisDFACreationHelper.createState()
        analysisDFACreationHelper.createTransitionBetween(firstState, secondState, SshSymbol.MSG_NEWKEYS)
        listOf(SshSymbol.MSG_KEXINIT, SshSymbol.MSG_NEWKEYS, SshSymbol.MSG_SERVICE_ACCEPT).forEach {
            analysisDFACreationHelper.createSelfTransition(firstState, it)
        }

        val thirdState = analysisDFACreationHelper.createState()
        analysisDFACreationHelper.createTransitionBetween(secondState, thirdState, SshSymbol.MSG_KEX_ECDH_REPLY)
        //analysisDFA.changeStateToAcceptAllInputSymbols(thirdState)

        return analysisDFACreationHelper
    }

    fun createAnalysisDFARun(): AnalysisDFARun = AnalysisDFARun(analysisDFACreationHelper)

}