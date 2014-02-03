if (Get-Module posh-git) { return }

Push-Location $psScriptRoot

. .\functions.ps1
Pop-Location

if (!$Env:HOME) { $Env:HOME = "$Env:HOMEDRIVE$Env:HOMEPATH" }
if (!$Env:HOME) { $Env:HOME = "$Env:USERPROFILE" }

Get-TempEnv 'SSH_AGENT_PID'
Get-TempEnv 'SSH_AUTH_SOCK'

Export-ModuleMember `
    -Alias @(
        '??') `
    -Function @(
        'Invoke-NullCoalescing',
        'Write-GitStatus',
        'Write-Prompt',
        'Get-GitStatus', 
        'Enable-GitColors', 
        'Get-GitDirectory',
        'TabExpansion',
        'Get-AliasPattern',
        'Get-SshAgent',
        'Start-SshAgent',
        'Stop-SshAgent',
        'Add-SshKey',
        'Get-SshPath',
        'Update-AllBranches',
        'tgit')


