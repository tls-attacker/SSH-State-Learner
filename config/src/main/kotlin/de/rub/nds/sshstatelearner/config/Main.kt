package de.rub.nds.sshstatelearner.config

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.ObjectMapper
import com.github.victools.jsonschema.generator.FieldScope
import com.github.victools.jsonschema.generator.OptionPreset
import com.github.victools.jsonschema.generator.SchemaGenerator
import com.github.victools.jsonschema.generator.SchemaGeneratorConfigBuilder
import com.github.victools.jsonschema.generator.SchemaVersion
import com.github.victools.jsonschema.module.jackson.JacksonModule
import com.github.victools.jsonschema.module.jackson.JacksonOption
import java.io.File

/**
 * Generates the schema json for the configuration classes.
 */
fun createConfigSchemaJson(outputDir: String) {
    fun addDefaultValueAnnotationProcessing(schemaGeneratorConfigBuilder: SchemaGeneratorConfigBuilder) {
        schemaGeneratorConfigBuilder.forFields().withDefaultResolver { field: FieldScope ->
            val annotation = field.getAnnotationConsideringFieldAndGetter(
                JsonProperty::class.java
            )
            if (annotation == null || annotation.defaultValue.isEmpty()) null else annotation.defaultValue
        }
    }

    val jacksonModule = JacksonModule(JacksonOption.RESPECT_JSONPROPERTY_REQUIRED)
    val schemaGeneratorConfigBuilder =
        SchemaGeneratorConfigBuilder(SchemaVersion.DRAFT_2020_12, OptionPreset.PLAIN_JSON)
            .with(jacksonModule)
    addDefaultValueAnnotationProcessing(schemaGeneratorConfigBuilder)
    val schemaGeneratorConfig = schemaGeneratorConfigBuilder.build()
    val schemaGenerator = SchemaGenerator(schemaGeneratorConfig)
    val configSchemaJson = schemaGenerator.generateSchema(ConfigGeneral::class.java)
    File("$outputDir/configGeneral.schema.json").writeText(configSchemaJson.toPrettyString())
}

/**
 * Generates a standard configuration file for each currently supported SUL
 */
fun createDefaultConfigs(outputDir: String) {
    val objectMapper = ObjectMapper()
    val prettyObjectWriter = objectMapper.writerWithDefaultPrettyPrinter()
    val configGeneral = ConfigGeneral()
    configGeneral.sulConfig = ConfigClientSul()
    prettyObjectWriter.writeValue(File(outputDir + "configClientSul.json"), configGeneral)

    configGeneral.sulConfig = ConfigServerSul()
    prettyObjectWriter.writeValue(File(outputDir + "configServerSul.json"), configGeneral)

    configGeneral.sulConfig = ConfigAndroidClientSul()
    prettyObjectWriter.writeValue(File(outputDir + "configAndroidClientSul.json"), configGeneral)
}

fun main() {
    val outputDir = "./src/main/resources/"
    createConfigSchemaJson(outputDir)
    createDefaultConfigs(outputDir)
}