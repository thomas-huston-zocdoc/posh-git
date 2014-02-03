# General Utility Functions

function Invoke-NullCoalescing {
    $result = $null
    foreach($arg in $args) {
        if ($arg -is [ScriptBlock]) {
            $result = & $arg
        } else {
            $result = $arg
        }
        if ($result) { break }
    }
    $result
}

Set-Alias ?? Invoke-NullCoalescing -Force

function Get-LocalOrParentPath($path) {
    $checkIn = Get-Item -Force .
    while ($checkIn -ne $NULL) {
        $pathToTest = [System.IO.Path]::Combine($checkIn.fullname, $path)
        if (Test-Path -LiteralPath $pathToTest) {
            return $pathToTest
        } else {
            $checkIn = $checkIn.parent
        }
    }
    return $null
}

function dbg ($Message, [Diagnostics.Stopwatch]$Stopwatch) {
    if($Stopwatch) {
        Write-Verbose ('{0:00000}:{1}' -f $Stopwatch.ElapsedMilliseconds,$Message) -Verbose # -ForegroundColor Yellow
    }
}





# Git Utility Functions

# Inspired by Mark Embling
# http://www.markembling.info/view/my-ideal-powershell-prompt-with-git-integration

function Get-GitDirectory {
    if ($Env:GIT_DIR) {
        $Env:GIT_DIR
    } else {
        Get-LocalOrParentPath .git
    }
}

function Get-GitBranch($gitDir = $(Get-GitDirectory), [Diagnostics.Stopwatch]$sw) {
    if ($gitDir) {
        dbg 'Finding branch' $sw
        $r = ''; $b = ''; $c = ''
        if (Test-Path $gitDir\rebase-merge\interactive) {
            dbg 'Found rebase-merge\interactive' $sw
            $r = '|REBASE-i'
            $b = "$(Get-Content $gitDir\rebase-merge\head-name)"
        } elseif (Test-Path $gitDir\rebase-merge) {
            dbg 'Found rebase-merge' $sw
            $r = '|REBASE-m'
            $b = "$(Get-Content $gitDir\rebase-merge\head-name)"
        } else {
            if (Test-Path $gitDir\rebase-apply) {
                dbg 'Found rebase-apply' $sw
                if (Test-Path $gitDir\rebase-apply\rebasing) {
                    dbg 'Found rebase-apply\rebasing' $sw
                    $r = '|REBASE'
                } elseif (Test-Path $gitDir\rebase-apply\applying) {
                    dbg 'Found rebase-apply\applying' $sw
                    $r = '|AM'
                } else {
                    dbg 'Found rebase-apply' $sw
                    $r = '|AM/REBASE'
                }
            } elseif (Test-Path $gitDir\MERGE_HEAD) {
                dbg 'Found MERGE_HEAD' $sw
                $r = '|MERGING'
            } elseif (Test-Path $gitDir\CHERRY_PICK_HEAD) {
                dbg 'Found CHERRY_PICK_HEAD' $sw
                $r = '|CHERRY-PICKING'
            } elseif (Test-Path $gitDir\BISECT_LOG) {
                dbg 'Found BISECT_LOG' $sw
                $r = '|BISECTING'
            }

            $b = Invoke-NullCoalescing `
                { dbg 'Trying symbolic-ref' $sw; git symbolic-ref HEAD 2>$null } `
                { '({0})' -f (Invoke-NullCoalescing `
                    {
                        dbg 'Trying describe' $sw
                        switch ($Global:GitPromptSettings.DescribeStyle) {
                            'contains' { git describe --contains HEAD 2>$null }
                            'branch' { git describe --contains --all HEAD 2>$null }
                            'describe' { git describe HEAD 2>$null }
                            default { git describe --tags --exact-match HEAD 2>$null }
                        }
                    } `
                    {
                        dbg 'Falling back on parsing HEAD' $sw
                        $ref = $null

                        if (Test-Path $gitDir\HEAD) {
                            dbg 'Reading from .git\HEAD' $sw
                            $ref = Get-Content $gitDir\HEAD 2>$null
                        } else {
                            dbg 'Trying rev-parse' $sw
                            $ref = git rev-parse HEAD 2>$null
                        }

                        if ($ref -match 'ref: (?<ref>.+)') {
                            return $Matches['ref']
                        } elseif ($ref -and $ref.Length -ge 7) {
                            return $ref.Substring(0,7)+'...'
                        } else {
                            return 'unknown'
                        }
                    }
                ) }
        }

        dbg 'Inside git directory?' $sw
        if ('true' -eq $(git rev-parse --is-inside-git-dir 2>$null)) {
            dbg 'Inside git directory' $sw
            if ('true' -eq $(git rev-parse --is-bare-repository 2>$null)) {
                $c = 'BARE:'
            } else {
                $b = 'GIT_DIR!'
            }
        }

        "$c$($b -replace 'refs/heads/','')$r"
    }
}

function Get-GitStatus($gitDir = (Get-GitDirectory)) {
    $settings = $Global:GitPromptSettings
    $enabled = (-not $settings) -or $settings.EnablePromptStatus
    if ($enabled -and $gitDir)
    {
        if($settings.Debug) {
            $sw = [Diagnostics.Stopwatch]::StartNew(); Write-Host ''
        } else {
            $sw = $null
        }
        $branch = $null
        $aheadBy = 0
        $behindBy = 0
        $indexAdded = @()
        $indexModified = @()
        $indexDeleted = @()
        $indexUnmerged = @()
        $filesAdded = @()
        $filesModified = @()
        $filesDeleted = @()
        $filesUnmerged = @()

        if($settings.EnableFileStatus -and !$(InDisabledRepository)) {
            dbg 'Getting status' $sw
            $status = git -c color.status=false status --short --branch 2>$null
        } else {
            $status = @()
        }

        dbg 'Parsing status' $sw
        $status | foreach {
            dbg "Status: $_" $sw
            if($_) {
                switch -regex ($_) {
                    '^(?<index>[^#])(?<working>.) (?<path1>.*?)(?: -> (?<path2>.*))?$' {
                        switch ($matches['index']) {
                            'A' { $indexAdded += $matches['path1'] }
                            'M' { $indexModified += $matches['path1'] }
                            'R' { $indexModified += $matches['path1'] }
                            'C' { $indexModified += $matches['path1'] }
                            'D' { $indexDeleted += $matches['path1'] }
                            'U' { $indexUnmerged += $matches['path1'] }
                        }
                        switch ($matches['working']) {
                            '?' { $filesAdded += $matches['path1'] }
                            'A' { $filesAdded += $matches['path1'] }
                            'M' { $filesModified += $matches['path1'] }
                            'D' { $filesDeleted += $matches['path1'] }
                            'U' { $filesUnmerged += $matches['path1'] }
                        }
                    }

                    '^## (?<branch>\S+?)(?:\.\.\.(?<upstream>\S+))?(?: \[(?:ahead (?<ahead>\d+))?(?:, )?(?:behind (?<behind>\d+))?\])?$' {
                        $branch = $matches['branch']
                        $upstream = $matches['upstream']
                        $aheadBy = [int]$matches['ahead']
                        $behindBy = [int]$matches['behind']
                    }

                    '^## Initial commit on (?<branch>\S+)$' {
                        $branch = $matches['branch']
                    }
                }
            }
        }

        if(!$branch) { $branch = Get-GitBranch $gitDir $sw }
        dbg 'Building status object' $sw
        $indexPaths = $indexAdded + $indexModified + $indexDeleted + $indexUnmerged
        $workingPaths = $filesAdded + $filesModified + $filesDeleted + $filesUnmerged
        $index = New-Object PSObject @(,@($indexPaths | ?{ $_ } | Select -Unique)) |
            Add-Member -PassThru NoteProperty Added    $indexAdded |
            Add-Member -PassThru NoteProperty Modified $indexModified |
            Add-Member -PassThru NoteProperty Deleted  $indexDeleted |
            Add-Member -PassThru NoteProperty Unmerged $indexUnmerged
        $working = New-Object PSObject @(,@($workingPaths | ?{ $_ } | Select -Unique)) |
            Add-Member -PassThru NoteProperty Added    $filesAdded |
            Add-Member -PassThru NoteProperty Modified $filesModified |
            Add-Member -PassThru NoteProperty Deleted  $filesDeleted |
            Add-Member -PassThru NoteProperty Unmerged $filesUnmerged

        $result = New-Object PSObject -Property @{
            GitDir          = $gitDir
            Branch          = $branch
            AheadBy         = $aheadBy
            BehindBy        = $behindBy
            HasIndex        = [bool]$index
            Index           = $index
            HasWorking      = [bool]$working
            Working         = $working
            HasUntracked    = [bool]$filesAdded
        }

        dbg 'Finished' $sw
        if($sw) { $sw.Stop() }
        return $result
    }
}

function InDisabledRepository {
    $currentLocation = Get-Location

    foreach ($repo in $Global:GitPromptSettings.RepositoriesInWhichToDisableFileStatus)
    {
        if ($currentLocation -like "$repo*") {
            return $true
        }
    }

    return $false
}

function Enable-GitColors {
    $env:TERM = 'cygwin'
}

function Get-AliasPattern($exe) {
   $aliases = @($exe) + @(Get-Alias | where { $_.Definition -eq $exe } | select -Exp Name)
   "($($aliases -join '|'))"
}

function setenv($key, $value) {
    [void][Environment]::SetEnvironmentVariable($key, $value, [EnvironmentVariableTarget]::Process)
    Set-TempEnv $key $value
}

function Get-TempEnv($key) {
    $path = Join-Path ($Env:TEMP) ".ssh\$key.env"
    if (Test-Path $path) {
        $value =  Get-Content $path
        [void][Environment]::SetEnvironmentVariable($key, $value, [EnvironmentVariableTarget]::Process)
    }
}

function Set-TempEnv($key, $value) {
    $path = Join-Path ($Env:TEMP) ".ssh\$key.env"
    if ($value -eq $null) {
        if (Test-Path $path) {
            Remove-Item $path
        }
    } else {
        New-Item $path -Force -ItemType File > $null
        $value > $path
    }
}

# Retrieve the current SSH agent PID (or zero). Can be used to determine if there
# is a running agent.
function Get-SshAgent() {
    $agentPid = $Env:SSH_AGENT_PID
    if ($agentPid) {
        $sshAgentProcess = Get-Process -Id $agentPid -ErrorAction SilentlyContinue
        if ($sshAgentProcess -and ($sshAgentProcess.Name -eq 'ssh-agent')) {
            return $agentPid
        } else {
            setenv 'SSH_AGENT_PID', $null
            setenv 'SSH_AUTH_SOCK', $null
        }
    }

    return 0
}

# Loosely based on bash script from http://help.github.com/ssh-key-passphrases/
function Start-SshAgent([switch]$Quiet) {
    [int]$agentPid = Get-SshAgent
    if ($agentPid -gt 0) {
        if (!$Quiet) { Write-Host "ssh-agent is already running (pid $($agentPid))" }
        return
    }

    $sshAgent = Get-Command ssh-agent -TotalCount 1 -ErrorAction SilentlyContinue
    if (!$sshAgent) { Write-Warning 'Could not find ssh-agent'; return }

    & $sshAgent | foreach {
        if($_ -match '(?<key>[^=]+)=(?<value>[^;]+);') {
            setenv $Matches['key'] $Matches['value']
        }
    }

    Add-SshKey
}

function Get-SshPath($File = 'id_rsa')
{
    $home = Resolve-Path (Invoke-NullCoalescing $Env:HOME ~)
    Resolve-Path (Join-Path $home ".ssh\$File") -ErrorAction SilentlyContinue 2> $null
}

# Add a key to the SSH agent
function Add-SshKey() {
    $sshAdd = Get-Command ssh-add -TotalCount 1 -ErrorAction SilentlyContinue
    if (!$sshAdd) { Write-Warning 'Could not find ssh-add'; return }

    if ($args.Count -eq 0) {
        & $sshAdd
    } else {
        foreach ($value in $args) {
            & $sshAdd $value
        }
    }
}

# Stop a running SSH agent
function Stop-SshAgent() {
    [int]$agentPid = Get-SshAgent
    if ($agentPid -gt 0) {
        # Stop agent process
        $proc = Get-Process -Id $agentPid
        if ($proc -ne $null) {
            Stop-Process $agentPid
        }

        setenv 'SSH_AGENT_PID', $null
        setenv 'SSH_AUTH_SOCK', $null
    }
}

function Update-AllBranches($Upstream = 'master', [switch]$Quiet) {
    $head = git rev-parse --abbrev-ref HEAD
    git checkout -q $Upstream
    $branches = (git branch --no-color --no-merged) | where { $_ -notmatch '^\* ' }
    foreach ($line in $branches) {
        $branch = $line.SubString(2)
        if (!$Quiet) { Write-Host "Rebasing $branch onto $Upstream..." }
        git rebase -q $Upstream $branch > $null 2> $null
        if ($LASTEXITCODE) {
            git rebase --abort
            Write-Warning "Rebase failed for $branch"
        }
    }
    git checkout -q $head
}





# Git Prompt

# Inspired by Mark Embling
# http://www.markembling.info/view/my-ideal-powershell-prompt-with-git-integration

$global:GitPromptSettings = New-Object PSObject -Property @{
    DefaultForegroundColor    = $Host.UI.RawUI.ForegroundColor

    BeforeText                = ' ['
    BeforeForegroundColor     = [ConsoleColor]::Yellow
    BeforeBackgroundColor     = $Host.UI.RawUI.BackgroundColor
    DelimText                 = ' |'
    DelimForegroundColor      = [ConsoleColor]::Yellow
    DelimBackgroundColor      = $Host.UI.RawUI.BackgroundColor

    AfterText                 = ']'
    AfterForegroundColor      = [ConsoleColor]::Yellow
    AfterBackgroundColor      = $Host.UI.RawUI.BackgroundColor

    BranchForegroundColor       = [ConsoleColor]::Cyan
    BranchBackgroundColor       = $Host.UI.RawUI.BackgroundColor
    BranchAheadForegroundColor  = [ConsoleColor]::Green
    BranchAheadBackgroundColor  = $Host.UI.RawUI.BackgroundColor
    BranchBehindForegroundColor = [ConsoleColor]::Red
    BranchBehindBackgroundColor = $Host.UI.RawUI.BackgroundColor
    BranchBehindAndAheadForegroundColor = [ConsoleColor]::Yellow
    BranchBehindAndAheadBackgroundColor = $Host.UI.RawUI.BackgroundColor

    BeforeIndexText           = ""
    BeforeIndexForegroundColor= [ConsoleColor]::DarkGreen
    BeforeIndexBackgroundColor= $Host.UI.RawUI.BackgroundColor

    IndexForegroundColor      = [ConsoleColor]::DarkGreen
    IndexBackgroundColor      = $Host.UI.RawUI.BackgroundColor

    WorkingForegroundColor    = [ConsoleColor]::DarkRed
    WorkingBackgroundColor    = $Host.UI.RawUI.BackgroundColor

    UntrackedText             = ' !'
    UntrackedForegroundColor  = [ConsoleColor]::DarkRed
    UntrackedBackgroundColor  = $Host.UI.RawUI.BackgroundColor

    ShowStatusWhenZero        = $true

    AutoRefreshIndex          = $true

    EnablePromptStatus        = !$Global:GitMissing
    EnableFileStatus          = $true
    RepositoriesInWhichToDisableFileStatus = @( ) # Array of repository paths
    DescribeStyle             = ''

    EnableWindowTitle         = 'posh~git ~ '

    Debug                     = $false
}

$WindowTitleSupported = $true
if (Get-Module NuGet) {
    $WindowTitleSupported = $false
}

function Write-Prompt($Object, $ForegroundColor, $BackgroundColor = -1) {
    if ($BackgroundColor -lt 0) {
        Write-Host $Object -NoNewLine -ForegroundColor $ForegroundColor
    } else {
        Write-Host $Object -NoNewLine -ForegroundColor $ForegroundColor -BackgroundColor $BackgroundColor
    }
}

function Write-GitStatus($status) {
    $s = $global:GitPromptSettings
    if ($status -and $s) {
        Write-Prompt $s.BeforeText -BackgroundColor $s.BeforeBackgroundColor -ForegroundColor $s.BeforeForegroundColor

        $branchBackgroundColor = $s.BranchBackgroundColor
        $branchForegroundColor = $s.BranchForegroundColor
        if ($status.BehindBy -gt 0 -and $status.AheadBy -gt 0) {
            # We are behind and ahead of remote
            $branchBackgroundColor = $s.BranchBehindAndAheadBackgroundColor
            $branchForegroundColor = $s.BranchBehindAndAheadForegroundColor
        } elseif ($status.BehindBy -gt 0) {
            # We are behind remote
            $branchBackgroundColor = $s.BranchBehindBackgroundColor
            $branchForegroundColor = $s.BranchBehindForegroundColor
        } elseif ($status.AheadBy -gt 0) {
            # We are ahead of remote
            $branchBackgroundColor = $s.BranchAheadBackgroundColor
            $branchForegroundColor = $s.BranchAheadForegroundColor
        }

        Write-Prompt $status.Branch -BackgroundColor $branchBackgroundColor -ForegroundColor $branchForegroundColor

        if($s.EnableFileStatus -and $status.HasIndex) {
            Write-Prompt $s.BeforeIndexText -BackgroundColor $s.BeforeIndexBackgroundColor -ForegroundColor $s.BeforeIndexForegroundColor

            if($s.ShowStatusWhenZero -or $status.Index.Added) {
              Write-Prompt " +$($status.Index.Added.Count)" -BackgroundColor $s.IndexBackgroundColor -ForegroundColor $s.IndexForegroundColor
            }
            if($s.ShowStatusWhenZero -or $status.Index.Modified) {
              Write-Prompt " ~$($status.Index.Modified.Count)" -BackgroundColor $s.IndexBackgroundColor -ForegroundColor $s.IndexForegroundColor
            }
            if($s.ShowStatusWhenZero -or $status.Index.Deleted) {
              Write-Prompt " -$($status.Index.Deleted.Count)" -BackgroundColor $s.IndexBackgroundColor -ForegroundColor $s.IndexForegroundColor
            }

            if ($status.Index.Unmerged) {
                Write-Prompt " !$($status.Index.Unmerged.Count)" -BackgroundColor $s.IndexBackgroundColor -ForegroundColor $s.IndexForegroundColor
            }

            if($status.HasWorking) {
                Write-Prompt $s.DelimText -BackgroundColor $s.DelimBackgroundColor -ForegroundColor $s.DelimForegroundColor
            }
        }

        if($s.EnableFileStatus -and $status.HasWorking) {
            if($s.ShowStatusWhenZero -or $status.Working.Added) {
              Write-Prompt " +$($status.Working.Added.Count)" -BackgroundColor $s.WorkingBackgroundColor -ForegroundColor $s.WorkingForegroundColor
            }
            if($s.ShowStatusWhenZero -or $status.Working.Modified) {
              Write-Prompt " ~$($status.Working.Modified.Count)" -BackgroundColor $s.WorkingBackgroundColor -ForegroundColor $s.WorkingForegroundColor
            }
            if($s.ShowStatusWhenZero -or $status.Working.Deleted) {
              Write-Prompt " -$($status.Working.Deleted.Count)" -BackgroundColor $s.WorkingBackgroundColor -ForegroundColor $s.WorkingForegroundColor
            }

            if ($status.Working.Unmerged) {
                Write-Prompt " !$($status.Working.Unmerged.Count)" -BackgroundColor $s.WorkingBackgroundColor -ForegroundColor $s.WorkingForegroundColor
            }
        }

        if ($status.HasUntracked) {
            Write-Prompt $s.UntrackedText -BackgroundColor $s.UntrackedBackgroundColor -ForegroundColor $s.UntrackedForegroundColor
        }

        Write-Prompt $s.AfterText -BackgroundColor $s.AfterBackgroundColor -ForegroundColor $s.AfterForegroundColor

        if ($WindowTitleSupported -and $s.EnableWindowTitle) {
            if( -not $Global:PreviousWindowTitle ) {
                $Global:PreviousWindowTitle = $Host.UI.RawUI.WindowTitle
            }
            $repoName = Split-Path -Leaf (Split-Path $status.GitDir)
            $prefix = if ($s.EnableWindowTitle -is [string]) { $s.EnableWindowTitle } else { '' }
            $Host.UI.RawUI.WindowTitle = "$prefix$repoName [$($status.Branch)]"
        }
    } elseif ( $Global:PreviousWindowTitle ) {
        $Host.UI.RawUI.WindowTitle = $Global:PreviousWindowTitle
    }
}

if(!(Test-Path Variable:Global:VcsPromptStatuses)) {
    $Global:VcsPromptStatuses = @()
}
function Global:Write-VcsStatus { $Global:VcsPromptStatuses | foreach { & $_ } }

# Add scriptblock that will execute for Write-VcsStatus
$Global:VcsPromptStatuses += {
    $Global:GitStatus = Get-GitStatus
    Write-GitStatus $GitStatus
}





# Git Tab Expansion

# Initial implementation by Jeremy Skinner
# http://www.jeremyskinner.co.uk/2010/03/07/using-git-with-windows-powershell/

$Global:GitTabSettings = New-Object PSObject -Property @{
    AllCommands = $false
}

$subcommands = @{
    bisect = 'start bad good skip reset visualize replay log run'
    notes = 'edit show'
    reflog = 'expire delete show'
    remote = 'add rename rm set-head show prune update'
    stash = 'list show drop pop apply branch save clear create'
    submodule = 'add status init update summary foreach sync'
    svn = 'init fetch clone rebase dcommit branch tag log blame find-rev set-tree create-ignore show-ignore mkdirs commit-diff info proplist propget show-externals gc reset'
    tfs = 'bootstrap checkin checkintool ct cleanup cleanup-workspaces clone diagnostics fetch help init pull quick-clone rcheckin shelve shelve-list unshelve verify'
    flow = 'init feature release hotfix'
}

$gitflowsubcommands = @{
    feature = 'list start finish publish track diff rebase checkout pull'
    release = 'list start finish publish track'
    hotfix = 'list start finish publish track'
}

function script:gitCmdOperations($commands, $command, $filter) {
    $commands.$command -split ' ' |
        where { $_ -like "$filter*" }
}


$script:someCommands = @('add','am','annotate','archive','bisect','blame','branch','bundle','checkout','cherry','cherry-pick','citool','clean','clone','commit','config','describe','diff','difftool','fetch','format-patch','gc','grep','gui','help','init','instaweb','log','merge','mergetool','mv','notes','prune','pull','push','rebase','reflog','remote','rerere','reset','revert','rm','shortlog','show','stash','status','submodule','svn','tag','whatchanged')
try {
  if ((git help -a 2>&1 | Select-String flow) -ne $null) {
      $script:someCommands += 'flow'
  }
}
catch {
}

function script:gitCommands($filter, $includeAliases) {
    $cmdList = @()
    if (-not $global:GitTabSettings.AllCommands) {
        $cmdList += $someCommands -like "$filter*"
    } else {
        $cmdList += git help --all |
            where { $_ -match '^  \S.*' } |
            foreach { $_.Split(' ', [StringSplitOptions]::RemoveEmptyEntries) } |
            where { $_ -like "$filter*" }
    }

    if ($includeAliases) {
        $cmdList += gitAliases $filter
    }
    $cmdList | sort
}

function script:gitRemotes($filter) {
    git remote |
        where { $_ -like "$filter*" }
}

function script:gitBranches($filter, $includeHEAD = $false) {
    $prefix = $null
    if ($filter -match "^(?<from>\S*\.{2,3})(?<to>.*)") {
        $prefix = $matches['from']
        $filter = $matches['to']
    }
    $branches = @(git branch --no-color | foreach { if($_ -match "^\*?\s*(?<ref>.*)") { $matches['ref'] } }) +
                @(git branch --no-color -r | foreach { if($_ -match "^  (?<ref>\S+)(?: -> .+)?") { $matches['ref'] } }) +
                @(if ($includeHEAD) { 'HEAD','FETCH_HEAD','ORIG_HEAD','MERGE_HEAD' })
    $branches |
        where { $_ -ne '(no branch)' -and $_ -like "$filter*" } |
        foreach { $prefix + $_ }
}

function script:gitFeatures($filter, $command){
    $featurePrefix = git config --local --get "gitflow.prefix.$command"
    $branches = @(git branch --no-color | foreach { if($_ -match "^\*?\s*$featurePrefix(?<ref>.*)") { $matches['ref'] } }) 
    $branches |
        where { $_ -ne '(no branch)' -and $_ -like "$filter*" } |
        foreach { $prefix + $_ }
}

function script:gitRemoteBranches($remote, $ref, $filter) {
    git branch --no-color -r |
        where { $_ -like "  $remote/$filter*" } |
        foreach { $ref + ($_ -replace "  $remote/","") }
}

function script:gitStashes($filter) {
    (git stash list) -replace ':.*','' |
        where { $_ -like "$filter*" } |
        foreach { "'$_'" }
}

function script:gitTfsShelvesets($filter) {
    (git tfs shelve-list) |
        where { $_ -like "$filter*" } |
        foreach { "'$_'" }
}

function script:gitFiles($filter, $files) {
    $files | sort |
        where { $_ -like "$filter*" } |
        foreach { if($_ -like '* *') { "'$_'" } else { $_ } }
}

function script:gitIndex($filter) {
    gitFiles $filter $GitStatus.Index
}

function script:gitAddFiles($filter) {
    gitFiles $filter (@($GitStatus.Working.Unmerged) + @($GitStatus.Working.Modified) + @($GitStatus.Working.Added))
}

function script:gitCheckoutFiles($filter) {
    gitFiles $filter (@($GitStatus.Working.Unmerged) + @($GitStatus.Working.Modified) + @($GitStatus.Working.Deleted))
}

function script:gitDiffFiles($filter, $staged) {
    if ($staged) {
        gitFiles $filter $GitStatus.Index.Modified
    } else {
        gitFiles $filter (@($GitStatus.Working.Unmerged) + @($GitStatus.Working.Modified) + @($GitStatus.Index.Modified))
    }
}

function script:gitMergeFiles($filter) {
    gitFiles $filter $GitStatus.Working.Unmerged
}

function script:gitDeleted($filter) {
    gitFiles $filter $GitStatus.Working.Deleted
}

function script:gitAliases($filter) {
    git config --get-regexp ^alias\. | foreach {
        if($_ -match "^alias\.(?<alias>\S+) .*") {
            $alias = $Matches['alias']
            if($alias -like "$filter*") {
                $alias
            }
        }
    } | Sort
}

function script:expandGitAlias($cmd, $rest) {
    if((git config --get-regexp "^alias\.$cmd`$") -match "^alias\.$cmd (?<cmd>[^!].*)`$") {
        return "git $($Matches['cmd'])$rest"
    } else {
        return "git $cmd$rest"
    }
}

function GitTabExpansion($lastBlock) {

    if($lastBlock -match "^$(Get-AliasPattern git) (?<cmd>\S+)(?<args> .*)$") {
        $lastBlock = expandGitAlias $Matches['cmd'] $Matches['args']
    }

    # Handles tgit <command> (tortoisegit)
    if($lastBlock -match "^$(Get-AliasPattern tgit) (?<cmd>\S*)$") {
            # Need return statement to prevent fall-through.
            return $tortoiseGitCommands | where { $_ -like "$($matches['cmd'])*" }
    }

    switch -regex ($lastBlock -replace "^$(Get-AliasPattern git) ","") {

        # Handles git <cmd> <op>
        "^(?<cmd>$($subcommands.Keys -join '|'))\s+(?<op>\S*)$" {
            gitCmdOperations $subcommands $matches['cmd'] $matches['op']
        }


        # Handles git flow <cmd> <op>
        "^flow (?<cmd>$($gitflowsubcommands.Keys -join '|'))\s+(?<op>\S*)$" {
            gitCmdOperations $gitflowsubcommands $matches['cmd'] $matches['op']
        }
        
        # Handles git flow <command> <op> <name>
        "^flow (?<command>\S*)\s+(?<op>\S*)\s+(?<name>\S*)$" {
            gitFeatures $matches['name'] $matches['command']
        }

        # Handles git remote (rename|rm|set-head|set-branches|set-url|show|prune) <stash>
        "^remote.* (?:rename|rm|set-head|set-branches|set-url|show|prune).* (?<remote>\S*)$" {
            gitRemotes $matches['remote']
        }

        # Handles git stash (show|apply|drop|pop|branch) <stash>
        "^stash (?:show|apply|drop|pop|branch).* (?<stash>\S*)$" {
            gitStashes $matches['stash']
        }

        # Handles git bisect (bad|good|reset|skip) <ref>
        "^bisect (?:bad|good|reset|skip).* (?<ref>\S*)$" {
            gitBranches $matches['ref'] $true
        }

        # Handles git tfs unshelve <shelveset>
        "^tfs +unshelve.* (?<shelveset>\S*)$" {
            gitTfsShelvesets $matches['shelveset']
        }

        # Handles git branch -d|-D|-m|-M <branch name>
        # Handles git branch <branch name> <start-point>
        "^branch.* (?<branch>\S*)$" {
            gitBranches $matches['branch']
        }

        # Handles git <cmd> (commands & aliases)
        "^(?<cmd>\S*)$" {
            gitCommands $matches['cmd'] $TRUE
        }

        # Handles git help <cmd> (commands only)
        "^help (?<cmd>\S*)$" {
            gitCommands $matches['cmd'] $FALSE
        }

        # Handles git push remote <ref>:<branch>
        "^push.* (?<remote>\S+) (?<ref>[^\s\:]*\:)(?<branch>\S*)$" {
            gitRemoteBranches $matches['remote'] $matches['ref'] $matches['branch']
        }

        # Handles git push remote <branch>
        # Handles git pull remote <branch>
        "^(?:push|pull).* (?:\S+) (?<branch>[^\s\:]*)$" {
            gitBranches $matches['branch']
        }

        # Handles git pull <remote>
        # Handles git push <remote>
        # Handles git fetch <remote>
        "^(?:push|pull|fetch).* (?<remote>\S*)$" {
            gitRemotes $matches['remote']
        }

        # Handles git reset HEAD <path>
        # Handles git reset HEAD -- <path>
        "^reset.* HEAD(?:\s+--)? (?<path>\S*)$" {
            gitIndex $matches['path']
        }

        # Handles git <cmd> <ref>
        "^commit.*-C\s+(?<ref>\S*)$" {
            gitBranches $matches['ref'] $true
        }

        # Handles git add <path>
        "^add.* (?<files>\S*)$" {
            gitAddFiles $matches['files']
        }

        # Handles git checkout -- <path>
        "^checkout.* -- (?<files>\S*)$" {
            gitCheckoutFiles $matches['files']
        }

        # Handles git rm <path>
        "^rm.* (?<index>\S*)$" {
            gitDeleted $matches['index']
        }

        # Handles git diff/difftool <path>
        "^(?:diff|difftool)(?:.* (?<staged>(?:--cached|--staged))|.*) (?<files>\S*)$" {
            gitDiffFiles $matches['files'] $matches['staged']
        }

        # Handles git merge/mergetool <path>
        "^(?:merge|mergetool).* (?<files>\S*)$" {
            gitMergeFiles $matches['files']
        }

        # Handles git <cmd> <ref>
        "^(?:checkout|cherry|cherry-pick|diff|difftool|log|merge|rebase|reflog\s+show|reset|revert|show).* (?<ref>\S*)$" {
            gitBranches $matches['ref'] $true
        }
    }
}

$PowerTab_RegisterTabExpansion = if (Get-Module -Name powertab) { Get-Command Register-TabExpansion -Module powertab -ErrorAction SilentlyContinue }
if ($PowerTab_RegisterTabExpansion)
{
    & $PowerTab_RegisterTabExpansion "git.exe" -Type Command {
        param($Context, [ref]$TabExpansionHasOutput, [ref]$QuoteSpaces)  # 1:

        $line = $Context.Line
        $lastBlock = [regex]::Split($line, '[|;]')[-1].TrimStart()
        $TabExpansionHasOutput.Value = $true
        GitTabExpansion $lastBlock
    }
    return
}

if (Test-Path Function:\TabExpansion) {
    Rename-Item Function:\TabExpansion TabExpansionBackup
}

function TabExpansion($line, $lastWord) {
    $lastBlock = [regex]::Split($line, '[|;]')[-1].TrimStart()

    switch -regex ($lastBlock) {
        # Execute git tab completion for all git-related commands
        "^$(Get-AliasPattern git) (.*)" { GitTabExpansion $lastBlock }
        "^$(Get-AliasPattern tgit) (.*)" { GitTabExpansion $lastBlock }

        # Fall back on existing tab expansion
        default { if (Test-Path Function:\TabExpansionBackup) { TabExpansionBackup $line $lastWord } }
    }
}





# TortoiseGit 

function private:Get-TortoiseGitPath {
  if ((Test-Path "C:\Program Files\TortoiseGit\bin\TortoiseGitProc.exe") -eq $true) {
    # TortoiseGit 1.8.0 renamed TortoiseProc to TortoiseGitProc.
    return "C:\Program Files\TortoiseGit\bin\TortoiseGitProc.exe"
  }

  return "C:\Program Files\TortoiseGit\bin\TortoiseProc.exe"
}

$Global:TortoiseGitSettings = new-object PSObject -Property @{
  TortoiseGitPath = (Get-TortoiseGitPath)
}

function tgit {
   if($args) {
    if($args[0] -eq "help") {
      # Replace the built-in help behaviour with just a list of commands
      $tortoiseGitCommands
      return    
    }

    $newArgs = @()
    $newArgs += "/command:" + $args[0]
    
    $cmd = $args[0]
    
    if($args.length -gt 1) {
      $args[1..$args.length] | % { $newArgs += $_ }
    }
      
    & $Global:TortoiseGitSettings.TortoiseGitPath $newArgs
  }
}

$tortoiseGitCommands = @(
"about",
"log",
"commit",
"add",
"revert",
"cleanup" ,
"resolve",
"switch",
"export",
"merge",
"settings",
"remove",
"rename",
"diff",
"conflicteditor",
"help",
"ignore",
"blame",
"cat",
"createpatch",
"pull",
"push",
"rebase",
"stashsave",
"stashapply",
"subadd",
"subupdate",
"subsync",
"reflog",
"refbrowse",
"sync",
"repostatus"
) | sort
