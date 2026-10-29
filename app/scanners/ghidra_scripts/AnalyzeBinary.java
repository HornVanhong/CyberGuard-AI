// Ghidra Headless Security Analysis & Decompiler Script for CyberGuard AI
//@category Security
//@author CyberGuard AI

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class AnalyzeBinary extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputPath = args.length > 0 ? args[0] : "ghidra_report.json";

        StringBuilder json = new StringBuilder();
        json.append("{\n");

        // Basic Metadata
        json.append("  \"program_name\": \"").append(escapeJson(currentProgram.getName())).append("\",\n");
        json.append("  \"language_id\": \"").append(escapeJson(currentProgram.getLanguageID().getIdAsString())).append("\",\n");
        json.append("  \"compiler\": \"").append(escapeJson(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString())).append("\",\n");
        json.append("  \"image_base\": \"0x").append(Long.toHexString(currentProgram.getImageBase().getOffset())).append("\",\n");
        json.append("  \"function_count\": ").append(currentProgram.getFunctionManager().getFunctionCount()).append(",\n");

        // High-Risk Windows / Linux API Cross-References
        List<String> targetApis = Arrays.asList(
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "WriteProcessMemory",
            "CreateRemoteThread", "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext",
            "WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW", "system",
            "URLDownloadToFileA", "URLDownloadToFileW", "InternetOpenA", "InternetOpenW",
            "HttpSendRequestA", "HttpSendRequestW", "WSAStartup", "connect", "send", "recv",
            "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent", "AdjustTokenPrivileges"
        );

        SymbolTable symTable = currentProgram.getSymbolTable();
        json.append("  \"detected_apis\": [\n");
        boolean firstApi = true;

        for (String targetApi : targetApis) {
            for (Symbol s : symTable.getSymbols(targetApi)) {
                if (!firstApi) json.append(",\n");
                firstApi = false;

                json.append("    {\n");
                json.append("      \"api\": \"").append(escapeJson(targetApi)).append("\",\n");
                json.append("      \"address\": \"").append(s.getAddress().toString()).append("\",\n");
                json.append("      \"callers\": [");

                Reference[] refs = s.getReferences();
                List<String> callers = new ArrayList<>();
                if (refs != null) {
                    for (Reference ref : refs) {
                        if (ref != null && ref.getFromAddress() != null) {
                            Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                            if (caller != null && !callers.contains(caller.getName())) {
                                callers.add(caller.getName());
                            }
                        }
                    }
                }

                for (int i = 0; i < callers.size(); i++) {
                    if (i > 0) json.append(", ");
                    json.append("\"").append(escapeJson(callers.get(i))).append("\"");
                }
                json.append("]\n");
                json.append("    }");
            }
        }
        json.append("\n  ],\n");

        // Decompile Entry Point / Main Function
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        Function targetFunc = currentProgram.getFunctionManager().getFunctionAt(currentProgram.getImageBase());
        if (targetFunc == null) {
            FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
            if (it.hasNext()) {
                targetFunc = it.next();
            }
        }

        if (targetFunc != null) {
            DecompileResults decompRes = decomp.decompileFunction(targetFunc, 30, monitor);
            if (decompRes != null && decompRes.decompileCompleted()) {
                String cCode = decompRes.getDecompiledFunction().getC();
                String[] lines = cCode.split("\n");
                StringBuilder snippet = new StringBuilder();
                for (int i = 0; i < Math.min(lines.length, 35); i++) {
                    snippet.append(lines[i]).append("\n");
                }
                json.append("  \"entry_function\": \"").append(escapeJson(targetFunc.getName())).append("\",\n");
                json.append("  \"decompiled_code\": \"").append(escapeJson(snippet.toString())).append("\"\n");
            } else {
                json.append("  \"entry_function\": \"").append(escapeJson(targetFunc.getName())).append("\",\n");
                json.append("  \"decompiled_code\": \"// Decompilation timed out or unavailable\"\n");
            }
        } else {
            json.append("  \"entry_function\": \"none\",\n");
            json.append("  \"decompiled_code\": \"// No functions identified\"\n");
        }
        decomp.dispose();

        json.append("}\n");

        // Write output
        try (PrintWriter writer = new PrintWriter(new FileWriter(outputPath))) {
            writer.print(json.toString());
        }
        println("[CyberGuard AI] Ghidra analysis report written to: " + outputPath);
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\b", "\\b")
                .replace("\f", "\\f")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
