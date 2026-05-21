package com.clearcapabilities.agenticsec

import com.intellij.openapi.project.Project
import com.redhat.devtools.lsp4ij.server.StreamConnectionProvider
import com.redhat.devtools.lsp4ij.server.ProcessStreamConnectionProvider
import com.redhat.devtools.lsp4ij.LanguageServerFactory

/**
 * Spawns the bundled `agentic-security-lsp` binary and pipes its stdio into
 * IntelliJ via LSP4IJ. The bin is expected on PATH (installed via
 * `npm i -g @clearcapabilities/agentic-security-scanner`); a setting
 * `agentic-security.lspCommand` overrides the path for non-global installs.
 */
class AgenticSecurityServerFactory : LanguageServerFactory {
    override fun createConnectionProvider(project: Project): StreamConnectionProvider {
        val cmd = System.getProperty("agentic-security.lspCommand")
            ?: "agentic-security-lsp"
        return ProcessStreamConnectionProvider(listOf(cmd), project.basePath)
    }
}
