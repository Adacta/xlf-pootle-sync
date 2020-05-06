<#
.SYNOPSIS
Short description

.DESCRIPTION
Long description

.EXAMPLE
An example

.NOTES
General notes
#>
function Sync-Pootle
{
    [CmdletBinding()]
    Param(
        # subfolder for source files
        [string]$source
        ,
        # trarget cultue
        [Parameter(Mandatory=$true)]
        [string]$targetCulture
        ,
        # Pootle SSH Server hostname
        [string]$pootleServer
        ,
        # Pootle SSH Server username
        [string]$pootleServerUsername
        ,
        # Pootle SSH Server password / key password
        [string]$pootleServerPassword
        ,
        # Pootle SSH Server SSH private key
        [string]$pootleServerKeyFile
        ,
        # Pootle translations root path
        [string]$pootleServerRootPath = "/pootle_translations/"
        ,
        # Pootle project code
        [string]$pootleServerProject
        ,
        # Delete files in sftp path for missing local source
        [bool]$pootleDeleteExcessFiles = $false
        ,
        # Skip upload from local to remote SSH
        [switch]
        $processUpload
        ,
        # Skip download operation from remote SSH to local
        [switch]
        $processDownload
    )
    
    #$VerbosePreference=[System.Management.Automation.ActionPreference]::Continue
    #Get-Variable | Out-String | Write-Verbose
    #ls env:| Out-String | Write-Verbose
    
    try
    {
        syntWithPootle
    }
    finally
    {
        popd
    }
}

function Install-SSH()
{
    $psg = Get-Module PowerShellGet
    if (!$psg -or $psg.Version -lt 1.6)
    {
        Install-Module -Scope CurrentUser -Name PowerShellGet -AllowClobber -Force -MinimumVersion 1.6 -Verbose
    }
    Import-Module PowerShellGet -MinimumVersion 1.6 -Verbose
    #$env:USERPROFILE\Documents\WindowsPowerShell\Modules\

    $ppNuget = Get-PackageProvider nuget
    if (!$ppNuget -or $ppNuget.Version -lt 2.8)
    {
        #Find-PackageProvider -Name nuget
        Install-PackageProvider -Scope CurrentUser -Name nuget -Force -MinimumVersion 2.8 -Verbose #-AllowClobber
        #$evn:LOCALAPPDATA\PackageManagement\
    }
    Import-PackageProvider -Name nuget -MinimumVersion 2.8 -ForceBootstrap # -Verbose
    # location saved to $env:APPDATA\NuGet\nuget.config

    Find-Package -ProviderName nuget -Name "SSH.NET" -Source https://www.nuget.org/api/v2 -MinimumVersion 2016 -Verbose 
    Install-Package -Scope CurrentUser -ProviderName nuget -Name "SSH.NET" -Source https://www.nuget.org/api/v2 -Force -ForceBootstrap -SkipDependencies -Verbose
    Import-Module SSH.NET
    #Find-Package -ProviderName nuget -Name "SSH.NET" -Verbose -MinimumVersion 2016
    #   
    #$packageSshNet = Find-Package -ProviderName nuget -Name "SSH.NET" -Source https://www.nuget.org/api/v2 -Verbose -AllVersions
    #$packageSshNet = Get-Package -ProviderName nuget -Name "SSH.NET" -Source https://www.nuget.org/api/v2 -Verbose -AllVersions
    #import-pa
}

function syntWithPootle()
{
    #$env:BUILD_REPOSITORY_LOCALPATH=(pwd)
    #$env:BUILD_BINARIESDIRECTORY=(Get-Item ..\b).FullName
    #$env:BUILD_ARTIFACTSTAGINGDIRECTORY=(Get-Item ..\a).FullName
    
    # https://www.visualstudio.com/en-us/docs/build/define/variables
    $root = Join-Path $env:BUILD_REPOSITORY_LOCALPATH $source
    $work = $env:BUILD_BINARIESDIRECTORY
    $artifacts = $env:BUILD_ARTIFACTSTAGINGDIRECTORY

    $sshDll = "SSH.NET\Renci.SshNet.dll"
    if (Test-Path $sshDll)
    {
        $sshDll = (Get-Item $sshDll).FullName
    }
    else
    {
        pushd $PSScriptRoot
        $fi = ls -Recurse -File Renci.SshNet.dll
        if ($fi -is [System.IO.FileInfo])
        {
            $sshDll = $fi.FullName
        }
        popd
    }

    Add-Type -Path $sshDll -ErrorAction Stop

    if ($pootleServerKeyFile)
    {
        $privateKeyFile = New-Object Renci.SshNet.PrivateKeyFile $pootleServerKeyFile, $pootleServerPassword
        
        $authMethod = New-Object Renci.SshNet.PrivateKeyAuthenticationMethod $pootleServerUsername, $privateKeyFile
    }
    elseif ($pootleServerPassword)
    {
        $authMethod = New-Object Renci.SshNet.PasswordAuthenticationMethod $pootleServerUsername, $pootleServerPassword
    }
    else
    {
        $authMethod = New-Object Renci.SshNet.NoneAuthenticationMethod $pootleServerUsername
    }

    $ci = New-Object Renci.SshNet.ConnectionInfo $pootleServer, $pootleServerUsername, $authMethod
    try
    {
        $sftp = New-Object Renci.SshNet.SftpClient $ci
        $sftp.KeepAliveInterval = "00:05:00"
        $sftp.Connect()

        $ssh = new-object Renci.SshNet.SshClient $ci
        $ssh.KeepAliveInterval = "00:05:00"
        $ssh.Connect()

        pushd $root
        if ($processUpload)
        {
            $xlfFilesToSync = @(ls $exportXlifRootTo -Recurse -File)
            transferTranslations $xlfFilesToSync -direction upload
            processShhCommand $ssh.RunCommand("sudo /opt/bitnami/apps/pootle/bin/pootle update_stores --noinput --project=$pootleServerProject --language=$targetCulture -v 3")
        }
        
        if ($processDownload)
        {
            processShhCommand $ssh.RunCommand("sudo /opt/bitnami/apps/pootle/bin/pootle sync_stores --noinput --project=$pootleServerProject --language=$targetCulture -v 3")
            processShhCommand $ssh.RunCommand("sudo chmod -R g+rw $pootleServerRootPath")

            $xlfFilesToSync = getRemoteFiles
            transferTranslations $xlfFilesToSync -direction download
        }
    }
    finally
    {
        $sftp.Disconnect()
        $sftp.Dispose()

        $ssh.Disconnect()
        $ssh.Dispose()
    }
}

function getRemoteFiles()
{
    $resultFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $sftpDir = $sftp.Get("$pootleServerRootPath/$pootleServerProject")
    $files = sftpListDirectoryRecursive "$($sftpDir.FullName)/$targetCulture"
    $files |% {
        #$file = $files[2]
        $file = $_
        $file = $file.Remove(0, $sftpDir.FullName.Length)
        $resultFiles.Add((Join-Path $exportXlifRootTo $file))
    }

    return $resultFiles
}

function sftpListDirectoryRecursive($remoteDir)
{
    $result = [System.Collections.Generic.List[string]]::new()
    if (!$sftp.Exists($remoteDir))
    {
        return
    }
    $files = $sftp.ListDirectory($remoteDir)
    $files |% {
        #$file = $files[2]
        $file = $_
        if ($file.FullName.EndsWith(".") -or $file.Name.StartsWith("."))
        {
            return
        }
        if ($file.IsDirectory)
        {
            Write-Verbose "Listing $($file.FullName)"
            [System.Collections.Generic.List[string]] $subResult = sftpListDirectoryRecursive $file.FullName
            if ($subResult)
            {
                $result.AddRange($subResult)
            }
        }
        elseif ($file.IsRegularFile)
        {
            $result.Add($file.FullName)
        }
    }

    return $result
}

function processShhCommand([Renci.SshNet.SshCommand]$sshCmd)
{
    if (!$sshCmd)
    {
        return
    }
    if ($sshCmd.ExitStatus -eq 0)
    {
        $sshCmd.Result
        Write-Verbose -Verbose $sshCmd.Error
    }
    else
    {
        Write-Error "Exit status $($sshCmd.ExitStatus) for '$($sshCmd.CommandText)'"
        $sshCmd.Result
        Write-Warning $sshCmd.Error
    }
}

function areFilesEqual([System.IO.FileInfo]$fi, $remoteFilename)
{
    $bothFilesHasSameHash = $false
    if ($sftp.Exists($remoteFilename) -and $fi.Exists)
    {
        $hashSftp = getSftpHash($remoteFilename)
        $hashLocal = (Get-FileHash $fi.FullName -Algorithm SHA256).Hash
        $bothFilesHasSameHash = [string]::Equals($hashSftp, $hashLocal, [System.StringComparison]::InvariantCultureIgnoreCase)
    }

    return $bothFilesHasSameHash
}

function transferTranslations([System.IO.FileInfo[]]$files, [ValidateSet("upload","download")][string]$direction = "upload")
{
    $uploadFoldersToSync = New-Object "System.Collections.Generic.Dictionary[System.IO.DirectoryInfo, string]"

    [System.IO.DirectoryInfo]$di = $exportXlifRootTo
    if (!$files)
    {
        return
    }
    $files | % {
        $fi = $_
        $relPath = $fi.Directory.FullName.Remove(0, $di.FullName.Length)
        $relPath = $relPath.Replace('\', '/').Replace('//', '/')
    
        $remoteDir = "$pootleServerRootPath/$pootleServerProject/$relPath"
        $remoteFilename = "$remoteDir/$($fi.Name)"
        try
        {
            if ($direction -eq "upload")
            {
                $bothFilesHasSameHash = areFilesEqual $fi $remoteFilename
                Write-Verbose -Verbose "$direction $($fi.FullName) to $remoteFilename (equal: $bothFilesHasSameHash)"
                if (!$bothFilesHasSameHash)
                {
                    if (!$sftp.Exists($remoteFilename))
                    {
                        processShhCommand $ssh.RunCommand("mkdir --parents ""$remoteDir""")
                    }
                    $file = $fi.OpenRead()
                    $sftp.UploadFile($file, $remoteFilename, $true)
                    $file.Dispose()
                    $file = $null
                }

                $uploadFoldersToSync[$fi.Directory] = $remoteDir
            }
            elseif ($direction -eq "download")
            {
                if ($sftp.Exists($remoteFilename))
                {
                    $bothFilesHasSameHash = areFilesEqual $fi $remoteFilename
                    Write-Verbose -Verbose "$direction $remoteFilename to $($fi.FullName) (equal: $bothFilesHasSameHash)"

                    if (!$bothFilesHasSameHash)
                    {
                        $fi.Directory.Create()
                        [System.IO.FileInfo]$tempFi = Join-Path $fi.Directory.FullName ([System.IO.Path]::GetRandomFileName())
                        $file = $tempFi.OpenWrite()
                        $sftp.DownloadFile($remoteFilename, $file)
                        $file.Dispose()
                        $file = $null
                        
                        Move-Item $tempFi.FullName $fi.FullName -Force
                    }
                }
                else
                {
                    Write-Warning "Missing remote file $remoteFilename"
                }
            }
            else
            {
                throw "Unsupported direction '$direction'"
            }
        }
        finally
        {
            if ($file)
            {
                $file.Dispose()
            }
            if ($tempFi -and $fi.Exists)
            {
                $tempFi.Delete()
            }
        }
    }

    if ($pootleDeleteExcessFiles -and $direction -eq "upload")
    {
        $uploadFoldersToSync.GetEnumerator() | % {deleteRemoteExcess -localPath $_.Key -remotePath $_.Value}
    }
}

function deleteRemoteExcess([System.IO.DirectoryInfo] $localPath, [string]$remotePath)
{
    $sftpFiles = $sftp.ListDirectory($remotePath)
    $sftpFiles | where {$_.Attributes.IsRegularFile} | % {
        [Renci.SshNet.Sftp.SftpFile]$sftpFile = $_
        if (!$localPath.GetFiles($sftpFile.Name))
        {
            Write-Verbose -Verbose "Delete remote file $($sftpFile.FullName)"
            $sftpFile.Delete()
        }
    }

}
    
function getSftpHash($remoteFilename)
{
    $hashResult = $ssh.RunCommand("sha256sum ""$remoteFilename""")
    if ($hashResult.ExitStatus -ne 0 -or [string]::IsNullOrWhiteSpace($hashResult.Result))
    {
        processShhCommand $hashResult
        throw "Error hash calculation for $remoteFilename"
    }
    $splitResult = $hashResult.Result.Split(" ", 2)

    return $splitResult[0]
}

Export-ModuleMember -Function Sync-Pootle
