/*
    CyberGuard AI - Harmless Test Fixtures Rule
    License: Apache-2.0
    Used strictly for testing the YARA compilation and match reporting pipeline.
*/

rule Synthetic_Harmless_Test_Rule
{
    meta:
        description = "Synthetic test indicator for pipeline validation"
        severity = "medium"
        author = "CyberGuard AI Automated Test"
    strings:
        $test_token = "CYBERGUARD_AI_BENIGN_TEST_PAYLOAD" ascii
    condition:
        $test_token
}
