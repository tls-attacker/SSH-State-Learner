package de.rub.nds.sshstatelearner.extraction

import de.rub.nds.sshstatelearner.sul.AdvancedStatisticSul
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.StringWriter
import java.io.Writer

@Serializable
data class Statistics(
    val states: Int,
    val counterExampleCount: Int,
    val learningStats: AdvancedStatisticSul.ImmutableData,
    val cacheInconsistencyRestarts: Int,
    val cacheHitRate: Double,
    val duration: Long
) {
    companion object {
        private val prettyJson = Json { prettyPrint = true }
    }

    override fun toString(): String =
        StringWriter().apply {
            export(this, pretty = false)
        }.toString()

    fun export(writer: Writer, pretty: Boolean = true) {
        if (pretty) {
            writer.write(prettyJson.encodeToString(this))
        } else {
            writer.write(Json.encodeToString(this))
        }
    }
}