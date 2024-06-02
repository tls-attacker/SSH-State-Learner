package de.rub.nds.sshstatelearner.analysis.limiter

import de.rub.nds.sshstatelearner.analysis.automata.AnalysisDFACreationHelper
import de.rub.nds.sshstatelearner.analysis.automata.AnalysisDFAReader
import de.rub.nds.sshstatelearner.analysis.automata.AnalysisDFARun

class DFASMLLimiter(val pathToFile: String) : SMLLimiter() {
    private lateinit var analysisDFACreationHelper: AnalysisDFACreationHelper

    override fun init() {
        this.analysisDFACreationHelper = AnalysisDFAReader().readJson(pathToFile)
    }

    override fun createSMLRun(): SMLRun = AnalysisDFARun(analysisDFACreationHelper)

}