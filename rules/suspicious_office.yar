/*
    CyberGuard AI - Suspicious Office Macro Rules
    License: Apache-2.0
*/

rule Office_VBA_Shell_Execution
{
    meta:
        description = "Detects Office documents combining auto-exec routines with Shell execution"
        severity = "high"
        author = "CyberGuard AI"
    strings:
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Document_Open" ascii nocase
        $auto3 = "Workbook_Open" ascii nocase
        $shell1 = "Shell(" ascii nocase
        $shell2 = "WScript.Shell" ascii nocase
        $shell3 = "CreateObject(\"WScript.Shell\")" ascii nocase
    condition:
        ($auto1 or $auto2 or $auto3) and ($shell1 or $shell2 or $shell3)
}
