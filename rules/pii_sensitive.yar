/*
 * pii_sensitive.yar
 * YARA rules for detecting PII and sensitive data leakage.
 * Used by yarax_scan.py in the sanitizer-engine pipeline.
 */

rule PII_SSN_Pattern
{
    meta:
        description = "Detects US Social Security Number patterns"
        severity     = "HIGH"
        category     = "pii"

    strings:
        // SSN: 123-45-6789 or 123 45 6789
        $ssn = /\b[0-9]{3}[-\s][0-9]{2}[-\s][0-9]{4}\b/ ascii

    condition:
        #ssn >= 3
}

rule PII_Credit_Card
{
    meta:
        description = "Detects credit card number patterns (Visa, MC, Amex, Discover)"
        severity     = "CRITICAL"
        category     = "pii"

    strings:
        // Visa: 4xxx xxxx xxxx xxxx
        $visa = /\b4[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/ ascii
        // Mastercard: 5[1-5]xx xxxx xxxx xxxx
        $mc   = /\b5[1-5][0-9]{2}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b/ ascii
        // Amex: 3[47]xx xxxxxx xxxxx
        $amex = /\b3[47][0-9]{2}[\s\-]?[0-9]{6}[\s\-]?[0-9]{5}\b/ ascii

    condition:
        any of them
}

rule PII_AWS_Access_Key
{
    meta:
        description = "Detects AWS access key patterns"
        severity     = "CRITICAL"
        category     = "secrets"

    strings:
        $key = /AKIA[0-9A-Z]{16}/ ascii

    condition:
        $key
}

rule PII_Generic_API_Key
{
    meta:
        description = "Detects generic API key / secret assignments"
        severity     = "HIGH"
        category     = "secrets"

    strings:
        $s1 = "api_key" ascii nocase
        $s2 = "api_secret" ascii nocase
        $s3 = "client_secret" ascii nocase
        $s4 = "access_token" ascii nocase
        $s5 = "private_key" ascii nocase
        // Must be followed by an assignment and a non-trivial value
        $assign = /[=:]\s*["']?[A-Za-z0-9\/+_\-]{20,}["']?/ ascii

    condition:
        any of ($s1, $s2, $s3, $s4, $s5) and $assign
}

rule PII_Private_Key_PEM
{
    meta:
        description = "Detects PEM-encoded private key material"
        severity     = "CRITICAL"
        category     = "secrets"

    strings:
        $pem1 = "-----BEGIN RSA PRIVATE KEY-----" ascii
        $pem2 = "-----BEGIN EC PRIVATE KEY-----" ascii
        $pem3 = "-----BEGIN PRIVATE KEY-----" ascii
        $pem4 = "-----BEGIN OPENSSH PRIVATE KEY-----" ascii

    condition:
        any of them
}

rule PII_Email_Address_Bulk
{
    meta:
        description = "Detects files containing 10+ distinct email addresses (potential data dump)"
        severity     = "MEDIUM"
        category     = "pii"

    strings:
        $email = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/ ascii

    condition:
        #email >= 10
}

rule PII_Password_In_Plaintext
{
    meta:
        description = "Detects plaintext password field assignments"
        severity     = "HIGH"
        category     = "secrets"

    strings:
        $p1 = "password=" ascii nocase
        $p2 = "passwd=" ascii nocase
        $p3 = "\"password\":" ascii nocase
        $p4 = "'password':" ascii nocase

    condition:
        any of them
}
