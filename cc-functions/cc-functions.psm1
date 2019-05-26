<#
    File Name          : CC-functions.psm1
    Author             : Bart Lievers
    Prerequisite       : PowerShell version : 2.0 - x
                         PS Modules and version : 
                            PowerCLI - 6.0 R2
    Version/GIT Tag    : v0.10.5
    Last Edit          : BL - 20-12-2015
    Copyright 2015 - CAM IT Solutions
#>    

#region defining custom types

#-- Type Syslog_Facility for function send-syslogmessage
Add-Type -TypeDefinition @"
	    public enum Syslog_Facility
	    {
		    kern,
		    user,
		    mail,
		    daemon,
		    auth,
		    syslog,
		    lpr,
		    news,
		    uucp,
		    clock,
		    authpriv,
		    ftp,
		    ntp,
		    logaudit,
		    logalert,
		    cron, 
		    local0,
		    local1,
		    local2,
		    local3,
		    local4,
		    local5,
		    local6,
		    local7
	    }
"@


#-- Type Syslog_Severity for function send-syslogmessage
Add-Type -TypeDefinition @"
	    public enum Syslog_Severity
	    {
		    Emergency,
		    Alert,
		    Critical,
		    Error,
		    Warning,
		    Notice,
		    Informational,
		    Debug
	    }
"@


#endregion
    
#region initialize functions for third party modules/snappins


    function import-PowerCLI {
        <#
        .SYNOPSIS
           Loading of all VMware modules and power snapins
        .DESCRIPTION
  
        .EXAMPLE
            One or more examples for how to use this script
        .NOTES
            File Name          : import-PowerCLI.ps1
            Author             : Bart Lievers
            Prerequisite       : <Preruiqisites like
                                 Min. PowerShell version : 2.0
                                 PS Modules and version : 
                                    PowerCLI - 6.0 R2
            Version/GIT Tag    : 1.0.0
            Last Edit          : BL - 3-1-2016
            CC-release         : 
            Copyright 2016 - CAM IT Solutions
        #>
        [CmdletBinding()]

        Param(
        )

        Begin{
 
        }

        Process{
            #-- make up inventory and check PowerCLI installation
            $RegisteredModules=Get-Module -Name vmware* -ListAvailable -ErrorAction ignore | % {$_.Name}
            $RegisteredSnapins=get-pssnapin -Registered vmware* -ErrorAction Ignore | %{$_.name}
            if (($RegisteredModules.Count -eq 0 ) -and ($RegisteredSnapins.count -eq 0 )) {
                #-- PowerCLI is not installed
                if ($log) {$log.warning("Cannot load PowerCLI, no VMware Powercli Modules and/or Snapins found.")}
                else {
                write-warning "Cannot load PowerCLI, no VMware Powercli Modules and/or Snapins found."}
                #-- exit function
                return $false
            }

            #-- load modules
            if ($RegisteredModules) {
                #-- make inventory of already loaded VMware modules
                $loaded = Get-Module -Name vmware* -ErrorAction Ignore | % {$_.Name}
                #-- make inventory of available VMware modules
                $registered = Get-Module -Name vmware* -ListAvailable -ErrorAction Ignore | % {$_.Name}
                #-- determine which modules needs to be loaded, and import them.
                $notLoaded = $registered | ? {$loaded -notcontains $_}

                foreach ($module in $registered) {
                    if ($loaded -notcontains $module) {
                        Import-Module $module -Global
                    }
                }
            }

            #-- load Snapins
            if ($RegisteredSnapins) {      
                #-- Exlude loaded modules from additional snappins to load
                $snapinList=Compare-Object -ReferenceObject $RegisteredModules -DifferenceObject $RegisteredSnapins | ?{$_.sideindicator -eq "=>"} | %{$_.inputobject}
                #-- Make inventory of loaded VMware Snapins
                $loaded = Get-PSSnapin -Name $snapinList -ErrorAction Ignore | % {$_.Name}
                #-- Make inventory of VMware Snapins that are registered
                $registered = Get-PSSnapin -Name $snapinList -Registered -ErrorAction Ignore  | % {$_.Name}
                #-- determine which snapins needs to loaded, and import them.
                $notLoaded = $registered | ? {$loaded -notcontains $_}

                foreach ($snapin in $registered) {
                    if ($loaded -notcontains $snapin) {
                        Add-PSSnapin $snapin
                    }
                }
            }
            #-- show loaded vmware modules and snapins
            if ($RegisteredModules) {get-module -Name vmware* | select name,version,@{N="type";E={"module"}} | ft -AutoSize}
              if ($RegisteredSnapins) {get-pssnapin -Name vmware* | select name,version,@{N="type";E={"snapin"}} | ft -AutoSize}

        }


        End{

        }



    #endregion
    }

    function remove-PowerCLI(){
        get-module vmware* | Remove-Module -Force -Confirm:$false
        get-pssnapin vmware* | Remove-PSSnapin -force -Confirm:$false
    }

#endregion

#region re-write global PowerShell functions
    function global:prompt{

        # change prompt text
        Write-Host "CAMCube " -NoNewLine -ForegroundColor Magenta
        Write-Host ((Get-location).Path + ">") -NoNewLine
        return " "
    }
#endregion

#region general script functions
    function exit-script {
    <#
    .DESCRIPTION
        Clean up actions before we exit the script.
    .PARAMETER unloadCcModule
        [switch] Unload the CC-function module
    .PARAMETER defaultcleanupcode
        [scriptblock] Unique code to invoke when exiting script.
    #>
    [CmdletBinding()]
    Param([switch]$unloadCCmodule,
          [scriptblock]$defaultcleanupcode)

    if ($finished_normal) {
        $msg= "Hooray.... finished without any bugs....."
        if ($log) {$log.verbose($msg)} else {Write-Verbose $msg}
    } else {
        $msg= "(1) Script ended with errors."
        if ($log) {$log.error($msg)} else {Write-Error $msg}
    }

    #-- General cleanup actions
    #-- disconnect vCenter connections if they exist
    if (Get-Variable -Scope global -Name DefaultVIServers -ErrorAction SilentlyContinue ) {
        Disconnect-VIServer -server * -Confirm:$false
    }
    #-- run unique code 
    if ($defaultcleanupcode) {
        $defaultcleanupcode.Invoke()
    }
    #-- unload CC-functions module from session
    if ($unloadCCmodule) { Get-Module -name cc-functions | Remove-Module}
    #-- Output runtime and say greetings
    $ts_end=get-date
    $msg="Runtime script: {0:hh}:{0:mm}:{0:ss}" -f ($ts_end- $ts_start)  
    if ($log) { $log.msg($msg)  } else {write-host $msg}
    read-host "The End <press Enter to close window>."
    exit
    }
#endregion

#region Elevated runspace

    function test-Elevated {
	    [CmdletBinding()]
	    param()
	    <#
	    .SYNOPSIS
	        Test if script is running in elevated runspace
	    .NOTES
	        Author: Bart Lievers
	        Date:   30 October 2013    
    #>	

	    # Get the ID and security principal of the current user account
	    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
	    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

	    # Get the security principal for the Administrator role
	    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

	    # Check to see if we are currently running "as Administrator"
		    return ($myWindowsPrincipal.IsInRole($adminRole))

    }

    function invoke-Elevated {
	    [CmdletBinding()]
	    param()
	    <#
	    .SYNOPSIS
	        Run current script in a new powershell runspace with elevated privileges.
	    .NOTES
	        Author: Bart Lievers
	        Date:   30 October 2013    
    #>
		
	    # Get the ID and security principal of the current user account
	    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
	    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)

	    # Get the security principal for the Administrator role
	    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator

	    # Check to see if we are currently running "as Administrator"
	    if ($myWindowsPrincipal.IsInRole($adminRole))
	       {
	       # We are running "as Administrator" - so change the title and background color to indicate this
	       $Host.UI.RawUI.WindowTitle = (split-path $myInvocation.scriptname -Leaf) + " (Elevated)"
	       clear-host
	       }  
    }
#endregion

#region log funstions

    function init-SysLogclient {
    <#
    .SYNOPSIS
        Copying syslog parameters from parameter object to global scope
    .EXAMPLE
        init-syslogclient
    #>
        param(
            [parameter(mandatory=$false)]$p=$p
        )


        $ParTable=@{}
        $partable["SysLog_Hostname"]=$P.SysLog_Hostname
        $partable["Syslog_Server"]=$P.Syslog_Server
        $partable["Syslog_default_Facility"]=$P.Syslog_default_Facility
        $partable["Syslog_Default_Severity"]=$P.Syslog_Default_Severity
        $partable["Syslog_Default_minSeverity"]=$P.Syslog_Default_minSeverity
        $partable["SysLog_default_UDPPort"]=$P.SysLog_default_UDPPort
        $partable["Syslog_default_ApplicationName"]=$P.Syslog_default_ApplicationName
        $partable["Log2Syslog"]=$P.Log2Syslog

        $partable.GetEnumerator() | %{
            $rcd=$_
        if (Get-Variable -Name $rcd.name -ErrorAction SilentlyContinue) {Get-Variable -Name $rcd.name | Remove-Variable -Confirm:$false }
            New-Variable -Name $rcd.name -Scope global -Value $rcd.Value
        }
    }

    function set-SysLogclient {
    <#
    .SYNOPSIS
        Define some default parameters for the send-syslog function
    .EXAMPLE
        set-SysLogclient -Hostname pietje -Server syslog.shire.lan -ApplicationName linux -DefaultFacility local3 -DefaultSeverity Informational 
    #>
        param(
            [parameter(mandatory=$true)][string]$Hostname,
            [parameter(mandatory=$true)][string]$Server,
            [string]$ApplicationName="-",
            [Syslog_Facility]$DefaultFacility="local7",
            [Syslog_Severity]$DefaultSeverity="Informational",
            [Syslog_Severity]$minSeverity="Informational",
            [int]$UDPPort=514
        )

        New-Variable -Name SysLog_Hostname -Scope global -Value $Hostname -Force
        New-Variable -Name Syslog_Server -Scope global -Value $Server -Force
        New-Variable -Name Syslog_default_Facility -Scope global -Value $DefaultFacility -Force
        New-Variable -Name Syslog_Default_Severity -Scope global -Value $DefaultSeverity -force
        New-Variable -Name Syslog_Default_minSeverity -Scope global -Value $minSeverity -force
        New-Variable -Name SysLog_default_UDPPort -Scope global -Value $UDPPort -Force
        New-Variable -Name Syslog_default_ApplicationName -Scope global -Value $ApplicationName -Force
    }

    function send-syslog{
    <#
    .SYNOPSIS
    Sends a SYSLOG message to a server running the SYSLOG daemon

    Use set-SysLogClient to set default parameters like server,facility,severity,udpport,hostname and applicationname
    .DESCRIPTION
    Sends a message to a SYSLOG server as defined in RFC 5424 and RFC 3164. 
    .PARAMETER Server
    Destination SYSLOG server that message is to be sent to.
    .PARAMETER Message
    Our message or content that we want to send to the server. This is option in RFC 5424, the CMDLet still has this as a madatory parameter, to send no message, simply specifiy '-' (as per RFC).
    .PARAMETER Severity
    Severity level as defined in SYSLOG specification, must be of ENUM type Syslog_Severity
    .PARAMETER Facility
    Facility of message as defined in SYSLOG specification, must be of ENUM type Syslog_Facility
    .PARAMETER Hostname
    Hostname of machine the mssage is about, if not specified, RFC 5425 selection rules will be followed.
    .PARAMETER ApplicationName
    Specify the name of the application or script that is sending the mesage. If not specified, will select the ScriptName, or if empty, powershell.exe will be sent. To send Null, specify '-' to meet RFC 5424. 
    .PARAMETER ProcessID
    ProcessID or PID of generator of message. Will automatically use $PID global variable. If you want to override this and send null, specify '-' to meet RFC 5424 rquirements. This is only sent for RFC 5424 messages.
    .PARAMETER MessageID
    Error message or troubleshooting number associated with the message being sent. If you want to override this and send null, specify '-' to meet RFC 5424 rquirements. This is only sent for RFC 5424 messages.
    .PARAMETER StructuredData
    Key Pairs of structured data as a string as defined in RFC5424. Default will be '-' which means null. This is only sent for RFC 5424 messages.
    .PARAMETER Timestamp
    Time and date of the message, must be of type DateTime. Correct format will be selected depending on RFC requested. If not specified, will call get-date to get appropriate date time.
    .PARAMETER UDPPort
    SYSLOG UDP port to send message to. Defaults to 514 if not specified.
    .PARAMETER RFC3164
    Send an RFC3164 fomatted message instead of RFC5424.
    .INPUTS
    Nothing can be piped directly into this function
    .OUTPUTS
    Nothing is output
    .EXAMPLE
    Send-SyslogMessage mySyslogserver "The server is down!" Emergency Mail
    Sends a syslog message to mysyslogserver, saying "server is down", severity emergency and facility is mail
    .NOTES
    NAME: Send-SyslogMessage
    AUTHOR: Kieran Jacobsen
    LASTEDIT: 2015 01 12
    KEYWORDS: syslog, messaging, notifications
    .LINK
    https://github.com/kjacobsen/PowershellSyslog
    .LINK
    http://poshsecurity.com
    #>
    [CMDLetBinding()]
    Param
    (
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String] 
	    $Server=$Syslog_Server,
	
	    [Parameter(
            Position=0,
            mandatory=$true,
            ValueFromPipeLine=$true,
            ValueFromPipeLineByPropertyName=$true)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $Message,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [Syslog_Severity]
	    $Severity=$Syslog_Default_Severity,

	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [Syslog_Severity]
	    $minSeverity=$Syslog_Default_minSeverity,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [Syslog_Facility] 
	    $Facility=$Syslog_default_Facility,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $Hostname = $Syslog_Hostname,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $ApplicationName = $Syslog_default_ApplicationName,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $ProcessID = $PID,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $MessageID = '-',
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [String]
	    $StructuredData = '-',
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
	    [DateTime] 
	    $Timestamp = [DateTime]::Now,
	
	    [Parameter(mandatory=$false)]
	    [ValidateNotNullOrEmpty()]
        [UInt16]
	    $UDPPort = 514,
	
	    [Parameter(mandatory=$false)]
	    [switch]
	    $RFC3164
    )
    if ($minSeverity -eq $null) {$minSeverity="informational"}
    if ($severity.value__ -gt $minSeverity.value__) {return}

    # Evaluate the facility and severity based on the enum types
    $Facility_Number = $Facility.value__
    $Severity_Number = $Severity.value__
    Write-Verbose "Syslog Facility, $Facility_Number, Severity is $Severity_Number"

    # Calculate the priority
    $Priority = ($Facility_Number * 8) + $Severity_Number
    Write-Verbose "Priority is $Priority"

    <#
    Application name or process name, simply find out if a script is calling the CMDLet, else use PowerShell
    #>
    if ($ApplicationName -eq '')
    {
        if ($scriptname -eq $null) {
            #-- no scriptname is defined, trying to deduct it.
            if (($myInvocation.ScriptName -ne $null) -and ($myInvocation.ScriptName -ne ''))
            {
                $ApplicationName = split-path -leaf $myInvocation.ScriptName
            }
        
            else
            {
                $ApplicationName = "PowerShell"
            }
        } else
        {
            $applicationName=$scriptname
        }
        Set-Variable -Name Syslog_default_ApplicationName -Scope global -Value $Applicationname
    }


    <#
    According to RFC 5424
    1.  FQDN
    2.  Static IP address
    3.  Hostname - Windows always has one of these
    4.  Dynamic IP address
    5.  the NILVALUE
    #>
    if ($hostname -eq '')
    {
	    if ($ENV:userdnsdomain -ne $null)
	    {
		    $hostname = $ENV:Computername + "." + $ENV:userdnsdomain
	    }
	    else
	    {
		    $hostname = $ENV:Computername
	    }
        Set-Variable -Name Syslog_hostname -Scope global -Value $hostname

    }

    if ($RFC3164)
    {
	    Write-Verbose 'Using RFC 3164 UNIX/BSD message format'
	    #Get the timestamp
	    $FormattedTimestamp = $Timestamp.ToString('MMM dd HH:mm:ss')
	    # Assemble the full syslog formatted Message
	    $FullSyslogMessage = "<{0}>{1} {2} {3} {4}" -f $Priority, $FormattedTimestamp, $Hostname, $ApplicationName, $Message

    }
    else
    {
	    Write-Verbose 'Using RFC 5424 IETF message format'
	    #Get the timestamp
	    $FormattedTimestamp = $Timestamp.ToString('yyyy-MM-ddTHH:mm:ss.ffffffzzz')
	    # Assemble the full syslog formatted Message
	    $FullSyslogMessage = "<{0}>1 {1} {2} {3} {4} {5} {6} {7}" -f $Priority, $FormattedTimestamp, $Hostname, $ApplicationName, $ProcessID, $MessageID, $StructuredData, $Message
    }

    Write-Verbose "Message to send will be $FullSyslogMessage"

    # create an ASCII Encoding object
    $Encoding = [System.Text.Encoding]::ASCII

    # Convert into byte array representation
    $ByteSyslogMessage = $Encoding.GetBytes($FullSyslogMessage)

    # If the message is too long, shorten it
    if ($ByteSyslogMessage.Length -gt 1024)
    {
        Write-Warning "Syslog Message too long, will be truncated."
        $ByteSyslogMessage = $ByteSyslogMessage.SubString(0, 1024)
    }

    # Create a UDP Client Object
    $UDPCLient = New-Object System.Net.Sockets.UdpClient
    $UDPCLient.Connect($Server, $UDPPort)

    # Send the Message
    $UDPCLient.Send($ByteSyslogMessage, $ByteSyslogMessage.Length) | Out-Null

    #Close the connection
    $UDPCLient.Close()
}

    function New-TimeStamp {
	    <#
			.SYNOPSIS  
			    Returns a timestamp based on the current date and time     
			.DESCRIPTION 
			    Returns a timestamp based on the current date and time 
			.NOTES  
			    Author         : Bart Lievers
			    Copyright 2013 - Bart Lievers
            .PARAMETER Sortable
                [switch] Make the timestamp sortable. like YYYYMMDD instead of DDMMYYYY
            .PARAMETER Serial
                [switch]  Remove seperation characters. Fur usage in filenames
            .PARAMETER noSeconds
                [switch] don't return the seconds in the timestamp
	    #>	
	    [cmdletbinding()]
	    param(
		    [switch]$Sortable,
		    [switch]$serial,
		    [switch]$noSeconds
		    )
		    $TimeFormat="%H:%M:%S"
		    if ($Sortable) {
			    $TimeFormat="%Y-%m-%d-%H:%M:%S"
		    } else {
			    $TimeFormat="%d-%m-%Y-%H:%M:%S"	
		    }
		    if($serial){
			    $TimeFormat=$TimeFormat.replace(":","").replace("-","")
		    }
		    if ($noSeconds) {
			    $TimeFormat=$TimeFormat.replace(":%S","").replace("%S","")
			
		    }
		    return (Get-Date -UFormat $TimeFormat)
		
    }
    
    Function New-LogObject {
	    <#
	    .SYNOPSIS  
	        Creating a text log file. Returning an object with methods to ad to the log     
	    .DESCRIPTION  
		    The function creates a new text file for logging. It returns an object with properties about the log file.	
		    and methods of adding logs entry
	    .NOTES  
	        Author         : Bart Lievers
	        Copyright 2013 - Bart Lievers   	
	    #>
	    [cmdletbinding()]
	    param(
	    [Parameter(Mandatory=$true,
		    helpmessage="The name of the eventlog to grab or create.")][string]$name,
	    [Parameter(Mandatory=$false,
		    helpmessage="Add a timestamp to the name of the logfile")][switch]$TimeStampLog,		
	    [Parameter(Mandatory=$false,
		    helpmessage="Location of log file. Default the %temp% folder.")]
		    [string]$location=$env:temp,	
	    [Parameter(Mandatory=$false,
		    helpmessage="File extension to be used. Default is .log")]
		    $extension=".log",
        [Parameter(Mandatory=$false)]
            [int]$keepNdays=14
	    )

        #-- verbose parameters
	    Write-Verbose "Input parameters"
	    Write-Verbose "`$name:$name"
	    Write-Verbose "`$location:$location"
	    Write-Verbose "`$extension:$extension"
	    Write-Verbose "`$keepNdays:$keepNdays"
	    Write-Verbose "`$TimeStampLog:$TimeStampLog"

        #-- determine log filename
	    if ($TimeStampLog) {
		    $Filename=((new-timestamp -serial -sortable -noSeconds )+"_"+$name+$extension)
	    } else {		
		    $Filename=$name+$extension
	    }
	    $FullFilename=$location + "\" +  $filename

	    write-host ("Log file : "+$fullfilename)
	    if (Test-Path -IsValid $FullFilename) {
            #-- filepath is valid
            $path=Split-Path -Path $FullFilename -Parent
            $ParentPath=Split-Path $FullFilename -Parent
            $folder=Split-Path -Path $ParentPath -Leaf
            if (! (Test-Path $path)) {
                #file path doesn't exist
                if ($ParentPath.length -gt 3) {
                    New-Item -Path $path -ItemType directory -Value $folder
                }
            }
        }
        else{
            Write-Warning "Invalid path for logfile location. $FullFilename"
            exit}
            	
        #-- create PS object
	    $obj = New-Object psobject
        #-- add properties to the object
        Add-Member -InputObject $obj -MemberType NoteProperty -Name file -Value $FullFilename
        Add-Member -InputObject $obj -MemberType NoteProperty -Name Name -Value $name
        Add-Member -InputObject $obj -MemberType NoteProperty -Name Location -Value $location
        Add-Member -InputObject $obj -MemberType ScriptMethod -Name write -Value {
		    param(
			    [string]$message
		    )
		    if (!($message)) {Out-File -FilePath $this.file -Append -InputObject ""} Else {
		    Out-File -FilePath $this.file -Append -Width $message.length -InputObject $message}}
	    Add-Member -InputObject $obj -MemberType ScriptMethod -Name create -value {
		    Out-File -FilePath $this.file -InputObject "======================================================================"
		    $this.write("")
		    $this.write("         name : "+ $this.name)		
		    $this.write("	  log file : " + $this.file)
		    $this.write("	created on : {0:dd-MMM-yyy hh:mm:ss}" -f (Get-Date))
		    $this.write("======================================================================")
	    }
        Add-Member -InputObject $obj -MemberType ScriptMethod -Name remove -value {
		    if (Test-Path $this.file) {Remove-Item $this.file}
	    }
        add-member -InputObject $obj -MemberType ScriptMethod -Name msg -Value {
		    param(
			    [string]$message
		    )	
		    if ((Test-Path $this.file) -eq $false) { $this.create()}
		    Write-Log -LogFile $this.file -message $message
	    }
        add-member -InputObject $obj -MemberType ScriptMethod -Name warning -Value {
		    param(
			    [string]$message
		    )	
		    if ((Test-Path $this.file) -eq $false) { $this.create()}	
		    Write-Log -LogFile $this.file -message $message -isWarning
	    }
        add-member -InputObject $obj -MemberType ScriptMethod -Name debug -Value {
		    param(
			    [string]$message
		    )	
		    if ((Test-Path $this.file) -eq $false) { $this.create()}	
		    Write-Log -LogFile $this.file -message $message -isDebug
	    }
        add-member -InputObject $obj -MemberType ScriptMethod -Name error -Value {
		    param(
			    [string]$message
		    )		
		    if ((Test-Path $this.file) -eq $false) { $this.create()}
		    Write-Log -LogFile $this.file -message $message -isError
	    }
        add-member -InputObject $obj -MemberType ScriptMethod -Name verbose -Value {
		    param(
			    [string]$message
		    )	
		    if ((Test-Path $this.file) -eq $false) { $this.create()}	
		    Write-Log -LogFile $this.file -message $message -isVerbose
	    }
        add-member -InputObject $obj -MemberType ScriptMethod -Name emptyline -Value {
		    param(
			    [string]$message
		    )	
		    if ((Test-Path $this.file) -eq $false) { $this.create()}	
		    Write-Log -LogFile $this.file  -EmptyLine
	    }

        #-- logfile cleanup maintenance
        clear-LogFiles -keepNdays $keepNdays -logObj $obj | Out-Null

        #-- create logfile
	    $obj.create() |out-null

        #-- return log object
        $obj
	    Return 
    }

    Function clear-LogFiles {
        <#
            .SYNOPSIS
                purge logfiles older then  specified days
            .DESCRIPTION
                purge logfiles older then  specified days.
                It expects a global variable called log. That variable should be created by the new-logobject function
            .PARAMETER keepNdays
                Keep the last N days of logfiles    
        #>
	    param(
		    [int]$keepNdays,
            [object]$logObj
	    )

        if ($logObj) {
            
        } else {
	        #-- check if global log variable exists
	        if ((Test-Path variable:global:log) -eq $false) {
		        Write-Error "Unable to purge old logfiles, cannot find global log variable."
		        exit
	        } else {
                $logobj=$log
            }
        }
        #-- check if log variable contains the location property
	    if ((test-path $logobj.Location) -eq $false) {
		    Write-Error "Log variable doesn't contain location property, cannot purge old logfiles."
		    exit	
	    }

        Write-Verbose ("Cleaning up old log files for "+$logobj.file)
        #-- determine date	
	    $limit = (Get-Date).AddDays(-$keepNdays)
	    $logobj.msg("Log files older then "+ $limit+ " will be removed.")
        #-- purge older logfiles
	    gci $logobj.Location | ? {	-not $_.PSIsContainer -and $_.CreationTime -lt $limit -and ($_.name -ilike ("*"+$logobj.name+".log")) } | Remove-Item
    }

    Function Write-Log {
	    <#
	    .SYNOPSIS  
	        Write message to logfile   
	    .DESCRIPTION 
	        Write message to logfile and associated output stream (error, warning, verbose etc...)
		    Each line in the logfile starts with a timestamp and loglevel indication.
		    The output to the different streams don't contain these prefixes.
		    The message is always sent to the verbose stream.
	    .NOTES  
	        Author         : Bart Lievers
	        Copyright 2013 - Bart Lievers 
	    .PARAMETER LogFilePath
		    The fullpath to the log file
	    .PARAMETER message
		    The message to log. It can be a multiline message
	    .Parameter NoTimeStamp
		    don't add a timestamp to the message
	    .PARAMETER isWarning
		    The message is a warning, it will be send to the warning stream
	    .PARAMETER isError
		    The message is an error message, it will be send to the error stream
	    .PARAMETER isDebug
		    The message is a debug message, it will be send to the debug stream.
	    .PARAMETER Emptyline
		    write an empty line to the logfile.
	    .PARAMETER toHost
		    write output also to host, when it has no level indication
	    #>	
	    [cmdletbinding()]
	    Param(
		    [Parameter(helpmessage="Location of logfile.",
					    Mandatory=$false,
					    position=1)]
		    [string]$LogFile=$LogFilePath,
		    [Parameter(helpmessage="Message to log.",
					    Mandatory=$false,
					    ValueFromPipeline = $true,
					    position=0)]
		    $message,
		    [Parameter(helpmessage="Log without timestamp.",
					    Mandatory=$false,
					    position=2)]
		    [switch]$NoTimeStamp,
		    [Parameter(helpmessage="Messagelevel is [warning]",
					    Mandatory=$false,
					    position=3)]
		    [switch]$isWarning,
		    [Parameter(helpmessage="Messagelevel is [error]",
					    Mandatory=$false,
					    position=4)]
		    [switch]$isError,
		    [Parameter(helpmessage="Messagelevel is [Debug]",
					    Mandatory=$false,
					    position=5)]
		    [switch]$isDebug,
		    [Parameter(helpmessage="Messagelevel is [Verbose]",
					    Mandatory=$false,
					    position=5)]
		    [switch]$isVerbose,
		    [Parameter(helpmessage="Write an empty line",
					    Mandatory=$false,
					    position=6)]
		    [switch]$EmptyLine
	    )
	    # Prepare the prefix
	    [string]$prefix=""
	    if ($isError) {$prefix ="[Error]       "}
	    elseif ($iswarning) {$prefix ="[Warning]     "}
	    elseif ($isDebug) {$prefix="[Debug]       "}
	    elseif ($isVerbose) {$prefix="[Verbose]     "}
	    else {$prefix ="[Information] "}
	    if (!($NoTimeStamp)) {
			    $prefix = ((new-TimeStamp) + " $prefix")}
	    if($EmptyLine) {
		    $msg =$prefix
	    } else {
		    $msg=$prefix+$message}
	    #-- handle multiple lines
	    $msg=[regex]::replace($msg, "`n`r","", "Singleline") #-- remove multiple blank lines
	    $msg=[regex]::Replace($msg, "`n", "`n"+$Prefix, "Singleline") #-- insert prefix in each line
	    #-- write message to logfile, if possible
	    if ($LogFile.length -gt 0) {
		    if (Test-Path $LogFile) {
			    $msg | Out-File -FilePath $LogFile -Append -Width $msg.length } 
		    else { Write-Warning "No valid log file (`$LogFilePath). Cannot write to log file."}
	    } 
	    else {
		    Write-Warning "No valid log file (`$LogFilePath). Cannot write to log file."
	    } 
	    #-- write message also to designated stream
	    if ($isError) {
                Write-Error $message
                if ($Log2SysLog) {Send-syslog -Message $message -Severity Alert}
                }
	    elseif ($iswarning) {
                Write-Warning $message
                if ($Log2SysLog) {Send-syslog -Message $message -Severity Warning}
                }
	    elseif ($isDebug) {
                Write-Debug $message
                if ($Log2SysLog) {Send-syslog -Message $message -Severity Debug}
                }
	    elseif ($isVerbose) {
                Write-Verbose $message           
                if ($Log2SysLog) {Send-syslog -Message $message -Severity Debug}
                }
	    else {Write-output $message                
                if ($Log2SysLog) {Send-syslog -Message $message -Severity Informational}
                }
    } 
 
#endregion

New-Alias  -name write-syslog -value Send-syslog -Description "write syslog message"

Export-ModuleMember -Function * -Alias *
