package de.rub.nds.sshstatelearner.cli.args;

import com.beust.jcommander.IStringConverter

class PortSplitter : IStringConverter<List<Int>> {
    override fun convert(value: String?): List<Int> {
        try {
            // Single port
            return listOf(Integer.parseInt(value))
        } catch (_: NumberFormatException) {}
        // Range of ports
        if (Regex("""\s*\d+\s*-\s*\d+\s*""").matches(value ?: "")) {
            val (start, end) = value!!.split("-").map { Integer.parseInt(it) }
            return (start..end).toList()
        }
        // List of ports
        return value?.split(",")
            ?.map { it.trim() }
            ?.map { Integer.parseInt(it) }
            ?: emptyList()
    }
}