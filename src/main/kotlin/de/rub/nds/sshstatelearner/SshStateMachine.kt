package de.rub.nds.sshstatelearner;

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
import net.automatalib.automata.transducers.MealyMachine
import net.automatalib.serialization.dot.GraphDOT
import net.automatalib.words.Alphabet
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import java.io.File
import java.io.IOException
import java.io.Writer

class SshStateMachine<S, T>(mealyMachine: MealyMachine<S, SshSymbol, T, ResponseFingerprint>, alphabet: Alphabet<SshSymbol>, private val stage: ProtocolStage)
    : StateMachine<S, SshSymbol, T, ResponseFingerprint>(mealyMachine, alphabet) {

    companion object {
        private val LOGGER: Logger = LogManager.getLogger()
    }

    override fun exportToDotAndPDF(graphFile: File, detail: VisualizationDetail) =
        exportToDotAndPDF(graphFile, detail, getEmptyGraphDetails())

    override fun exportToDot(writer: Writer, detail: VisualizationDetail) =
        exportToDot(writer, detail, getEmptyGraphDetails())

    override fun exportToDot(writer: Writer, detail: VisualizationDetail, graphDetails: GraphDetails<S, SshSymbol, T>) {
        try {
            GraphDOT.write(
                mealyMachine.transitionGraphView(alphabet),
                writer,
                SSHDOTVisualizationHelper(
                    ShortMealyVisualizationHelper(mealyMachine, graphDetails, detail),
                    // TODO: Use the correct server title
                    "Test",
                    alphabet
                )
            )
            writer.close()
        } catch (e: IOException) {
            LOGGER.warn("Caught an IOException while exporting mealy machine to DOT file", e)
        }
    }

    private fun getEmptyGraphDetails(): GraphDetails<S, SshSymbol, T> {
        return when(stage) {
            ProtocolStage.TRANSPORT -> SshTransportGraphDetails()
            ProtocolStage.AUTHENTICATION -> SshAuthenticationGraphDetails()
            ProtocolStage.CONNECTION -> SshConnectionGraphDetails()
        }
    }
}
