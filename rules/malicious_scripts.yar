/*
    CyberGuard AI - Malicious Script Detection Rules
    License: Apache-2.0
*/

rule WebShell_PHP_Generic
{
    meta:
        description = "Detects generic PHP webshell execution patterns"
        severity = "high"
        author = "CyberGuard AI"
    strings:
        $eval = "eval(" ascii nocase
        $b64 = "base64_decode(" ascii nocase
        $post = "$_POST[" ascii
        $req = "$_REQUEST[" ascii
        $shell = "shell_exec(" ascii nocase
        $passthru = "passthru(" ascii nocase
        $system = "system(" ascii nocase
    condition:
        ($eval and $b64 and ($post or $req)) or
        (($shell or $passthru or $system) and ($post or $req))
}

rule PowerShell_Suspicious_Download_Exec
{
    meta:
        description = "Detects PowerShell one-liner download and execute commands"
        severity = "high"
        author = "CyberGuard AI"
    strings:
        $ps1 = "powershell" ascii nocase
        $dl1 = "DownloadString(" ascii nocase
        $dl2 = "DownloadFile(" ascii nocase
        $iex1 = "IEX" ascii nocase
        $iex2 = "Invoke-Expression" ascii nocase
        $hidden = "-WindowStyle Hidden" ascii nocase
        $bypass = "-ExecutionPolicy Bypass" ascii nocase
    condition:
        $ps1 and ($dl1 or $dl2) and ($iex1 or $iex2) and ($hidden or $bypass)
}

rule Linux_Reverse_Shell_Patterns
{
    meta:
        description = "Detects classic Unix reverse shell patterns"
        severity = "critical"
        author = "CyberGuard AI"
    strings:
        $sh1 = "/bin/sh -i" ascii
        $sh2 = "/bin/bash -i" ascii
        $tcp = "/dev/tcp/" ascii
        $fifo = "mkfifo /tmp/" ascii
        $nc = "nc -e /bin/" ascii
    condition:
        ($tcp and ($sh1 or $sh2)) or $fifo or $nc
}
