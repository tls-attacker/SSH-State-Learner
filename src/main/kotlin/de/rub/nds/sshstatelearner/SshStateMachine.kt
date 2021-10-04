package de.rub.nds.sshstatelearner;

import de.rub.nds.sshattacker.core.constants.KeyExchangeAlgorithm
import de.rub.nds.sshstatelearner.analysis.analyzer.SshAuthenticationAnalyzer
import de.rub.nds.sshstatelearner.analysis.analyzer.SshConnectionAnalyzer
import de.rub.nds.sshstatelearner.analysis.analyzer.SshTransportAnalyzer
import de.rub.nds.sshstatelearner.analysis.data.GraphDetails
import de.rub.nds.sshstatelearner.analysis.data.SshAuthenticationGraphDetails
import de.rub.nds.sshstatelearner.analysis.data.SshConnectionGraphDetails
import de.rub.nds.sshstatelearner.analysis.data.SshTransportGraphDetails
import de.rub.nds.sshstatelearner.constants.VisualizationDetail
import de.rub.nds.sshstatelearner.extraction.SshSymbol
import de.rub.nds.sshstatelearner.sul.ProtocolStage
import de.rub.nds.sshstatelearner.sul.response.ResponseFingerprint
import de.rub.nds.sshstatelearner.visualization.SSHDOTVisualizationHelper
import de.rub.nds.sshstatelearner.visualization.ShortMealyVisualizationHelper
import net.automatalib.automata.graphs.TransitionEdge
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.serialization.dot.DOTVisualizationHelper
import net.automatalib.serialization.dot.GraphDOT
import net.automatalib.words.Alphabet
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.File
import java.io.IOException
import java.io.Writer

class SshStateMachine<S, T>(
    mealyMachine: MealyMachine<S, SshSymbol, T, ResponseFingerprint>,
    alphabet: Alphabet<SshSymbol>,
    val title: String,
    val stage: ProtocolStage,
    val kexAlgorithm: KeyExchangeAlgorithm
) : StateMachine<S, SshSymbol, T, ResponseFingerprint>(
    mealyMachine,
    alphabet
) {

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    override var graphDetails: GraphDetails<S, SshSymbol, T> = getEmptyGraphDetails()

    override fun getVisualizationHelper(detail: VisualizationDetail): DOTVisualizationHelper<S, TransitionEdge<SshSymbol, T>> =
        SSHDOTVisualizationHelper(
            ShortMealyVisualizationHelper(mealyMachine, alphabet, graphDetails, detail),
            title,
            alphabet,
            stage,
            kexAlgorithm
        )

    private fun getEmptyGraphDetails(): GraphDetails<S, SshSymbol, T> {
        return when(stage) {
            ProtocolStage.TRANSPORT -> SshTransportGraphDetails()
            ProtocolStage.AUTHENTICATION -> SshAuthenticationGraphDetails()
            ProtocolStage.CONNECTION -> SshConnectionGraphDetails()
        }
    }

    override fun analyzeMealyMachine() {
        when(stage) {
            ProtocolStage.TRANSPORT -> SshTransportAnalyzer<S, T>().analyze(this)
            ProtocolStage.AUTHENTICATION -> SshAuthenticationAnalyzer<S, T>().analyze(this)
            ProtocolStage.CONNECTION -> SshConnectionAnalyzer<S, T>().analyze(this)
        }
    }
}
