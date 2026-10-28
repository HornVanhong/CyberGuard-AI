/*
    CyberGuard AI - Suspicious PE Executable Rules
    License: Apache-2.0
*/

rule Suspicious_UPX_Packed_Binary
{
    meta:
        description = "Identifies PE binaries packed with UPX"
        severity = "medium"
        author = "CyberGuard AI"
    strings:
        $mz = "MZ"
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx_sig = "!UPX!" ascii
    condition:
        $mz at 0 and ($upx0 or $upx1 or $upx_sig)
}

rule Ransomware_Note_Artifacts
{
    meta:
        description = "Detects common ransomware payment and ransom note indicators"
        severity = "critical"
        author = "CyberGuard AI"
    strings:
        $s1 = "All your files have been encrypted" ascii nocase
        $s2 = "Your files are encrypted with military grade" ascii nocase
        $s3 = "TOR browser" ascii nocase
        $s4 = ".onion" ascii nocase
        $s5 = "bitcoin" ascii nocase
        $s6 = "decrypt your files" ascii nocase
    condition:
        3 of ($s1, $s2, $s3, $s4, $s5, $s6)
}
