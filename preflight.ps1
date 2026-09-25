<#
.SYNOPSIS
    AegisPQC pre-flight validation.

.DESCRIPTION
    Answers one question: is this prototype safe to present right now?

    Every check exercises a real code path rather than confirming a file exists.
    Run it before you walk into the room.

.PARAMETER Fast
    Skip the full test suite. Takes about 10 seconds instead of about 60.

.EXAMPLE
    .\preflight.ps1
    .\preflight.ps1 -Fast
#>

param(
    [switch]$Fast
)

$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

# Prefer the project virtual environment if it exists.
if (Test-Path ".\.venv\Scripts\Activate.ps1") {
    & ".\.venv\Scripts\Activate.ps1"
}

if ($Fast) {
    python -m backend.preflight --fast
} else {
    python -m backend.preflight
}

exit $LASTEXITCODE
