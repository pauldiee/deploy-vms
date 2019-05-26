<#
.SYNOPSIS
   Batch deployment of VMs based on a VM Template
.DESCRIPTION
   The purpose of this script is to deploy a batch of VMs and configure them 
   according to specs in the parameters.ps1 file and a csv file.

   The script uses a production line flow. The line consists of several work area's/queues.
   The VMs (as described in the CSV) go through this production line. 
   For each area/queue a VM knows a defined set of states.
   These are :
        - wait | VM / task is waiting to be processed
        - start | VM / task started to execute
        - busy | VM / task is busy
        - Failed | VM / task failed
        - Done | VM / task finished execution and moved to next area/queue with status wait
        - Delayed | VM / Task
        - Skipped | VM / Task is skipped and status is set to Done.
    When the next queue is the queue 'Finished' the task will be marked done and put in the Finished Queue.
    The execution of the script is complete when the sum of the queues Finished, 
    Failed and skipped is equal to the amount of VMs to deploy.

.EXAMPLE
    >deploy-VMs.ps1
.NOTES
    File Name          : deploy-VMs.ps1
    Author             : Bart Lievers
    Prerequisite       : 
                         PowerShell version : 3.0
                         PowerCLI 5.8
    Last Edit          : BL - 13-6-2017
    Version            : 1.1.0
    Copyright 2016 - CAM IT Solutions

#>
[CmdletBinding()]

Param(
)

Begin{
    #-- initialize environment
    $DebugPreference="SilentlyContinue"
    $VerbosePreference="Continue"
    $ErrorActionPreference="Continue"
    $WarningPreference="Continue"
    clear-host #-- clear CLi
    $ts_start=get-date #-- note start time of script
    if ($finished_normal) {Remove-Variable -Name finished_normal -Confirm:$false }

	#-- determine script location and name
	$scriptpath=get-item (Split-Path -parent $MyInvocation.MyCommand.Definition)
	$scriptname=(Split-Path -Leaf $MyInvocation.mycommand.path).Split(".")[0]

    #-- load default CAMCube functions
    Import-Module $scriptpath\cc-functions\cc-functions.psm1 -Force -global

    #-- Load Parameterfile
    $P = & $scriptpath\parameters.ps1
    if ($P.Log2SysLog) {init-SysLogclient}

    #-- create log file and cleanup old log files
    $log=New-LogObject -name $scriptname -TimeStampLog -location $P.LogPath -keepNdays $P.LogDays
    $log.verbose("Script started at {0:HH}:{0:mm}:{0:ss}" -f $ts_start)
    if ($P.openlog -and (Test-Path $p.NotePad)) {
        start-process $p.NotePad -argumentlist $log.file
    }
    
    #-- logging parameter settings
    $log.verbose( "--- Loaded Parameters ---")
    $P.GetEnumerator() | sort name | %{$log.verbose($_.name + " : " + $_.value)}
    $log.verbose("-----")



#region for Private script functions
    #-- note: place any specific function in this region


    function exit-script {
    <#
    .DESCRIPTION
        Clean up actions before we exit the script.
    #>
    [CmdletBinding()]
    Param()
    #-- disconnect vCenter connections (if there are any)
    if ((Get-Variable -Scope global -Name DefaultVIServers -ErrorAction SilentlyContinue ).value) {
        Disconnect-VIServer -server * -Confirm:$false
    }
    #-- clock time and say bye bye
    $ts_end=get-date
 #   write-host ("Runtime script: {0:hh}:{0:mm}:{0:ss}" -f ($ts_end- $TS_start)  )
    $log.msg("Runtime script: {0:hh}:{0:mm}:{0:ss}" -f ($ts_end- $TS_start)  )
    read-host "Einde script. bye bye ([Enter] to quit.)"
    exit
    }


    function import-tasktable {
    param(
        [string]$CSVFile="",
        $CSVDelimiter,
        $refHeader
    )

    #-- import CSV
        # check if a full path is given, else assume $scriptpath as the parent folder
    if ($CSVFile -inotmatch "[\\|\/]") {
        $csvfile=$scriptpath.fullname+"\"+$csvfile
        }
    if (!(Test-Path $CSVFile)) {
        $log.warning($CSVFile+" niet vinden gevonden.")
        $csvfile = get-childitem -Path $scriptpath -Filter *.csv |Out-GridView -Title "Selecteer het CSV bestand met VMs om uit te rollen." -OutputMode Single
        if (!(Test-Path $CSVFile)) {
            $log.verbose("Geen geldige input voor CSV bestand.")
            exit-script
        }
    }
    [Array]$tasktable = Import-Csv -Path $CSVFile -Delimiter $CSVDelimiter

    #-- check if the imported CSV has a valid header
    $Headercheck=$true
    $header=$tasktable[0] | gm -MemberType NoteProperty | select -ExpandProperty name 

    $MissingFields=(Compare-Object -ReferenceObject $refHeader -DifferenceObject $header) | ?{$_.sideindicator -ilike "<="}
    if ((Compare-Object -ReferenceObject $refHeader -DifferenceObject $header) | ?{$_.sideindicator -ilike "<="}) {
        # We are missing some names in the header
        $log.warning($P.CSVfile +" is missing some headers, missing headers are:")
        $log.warning($missingFields.inputobject)
        exit-script
    }
    return $tasktable
    }

    function Test-FileLock {
	    #-- test if file is locked
      param (
		    [parameter(Mandatory=$true, helpmessage="Full path of file to be tested (including file name)")]
		    [string]$Path
	    )

      $oFile = New-Object System.IO.FileInfo $Path
      if ((Test-Path -Path $Path) -eq $false)
      { #-- file isn't found, answer of test is false
  	    $false
  	    return
      }
  
      try #-- test if file is locked, when locked error will be caught
      {
	      $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) #-- try accessing the file
	      if ($oStream)
	      {
	        $oStream.Close() #-- close the file, if possible)
	      }
	      $false #-- file is not being locked.
      }
      catch
      { #-- there was an exeption triggered while trying to acces the file, so it is being used.
  	    # file is locked by a process.
  	    $true
      }
  }

    function Update-toHTMLStatus {
	    [CmdletBinding()]
	    #-- export object to HTML file, including changes with last values
	    param (
		    [string]$varName, #-- name of variable to report 
		    [string]$OutputFile=$env:TEMP+"\"+(Get-Random)+".htm", #-- default location of HTML file is temp directory.
		    [int]$refreshtimeHTML=10,
		    [switch]$force,
		    [switch]$noRefresh
	    )
	
	    if (!(Test-Path "variable:$varName")) {
		    exit #-- exit function when variable is not found
	    }	
	    $CurrentVal = Get-Variable -Name $varName -ValueOnly #-- get actual value of variable
	    #-- try to stop caching HTML file by brower
	    $refreshpage=$refreshtimeHTML #-- HTML page refreshes every 2 seconds
	    if ($noRefresh -eq $false) {
		    $HTMLHeader= '<meta http-equiv="refresh" content="'+$refreshpage+'">'}
	    $HTMLHeader= $HTMLHeader+ '	<META HTTP-EQUIV="Pragma" CONTENT="no-cache">
					    <META HTTP-EQUIV="Expires" CONTENT="-1">'	
	
	    #-- load or build object to store previous values and to compare actual value with
	    if (Test-Path  Variable:HTMLArch)	{$tempvar = Get-Variable -Name HTMLArch -Scope global -ValueOnly }
	    $NewMember=$true
	    if (Test-Path  Variable:HTMLArch)	{ #-- the archive object exists,
		    $tempvar = Get-Variable -Name HTMLArch -Scope global -ValueOnly #-- get the value of the archive object
		    $HTMLArch | gm  -MemberType NoteProperty | %{if ($_.name -like $varName) {$NewMember=$false}}} #-- check if archive object contains info about variable to compare
	    if($NewMember) { #-- variable not found in archive object, build structure for it
		    if ((Test-Path Variable:tempvar) -eq $false) {
			    $tempvar = New-Object -TypeName pscustomobject
		    }
		    $PrevValue = New-Object -TypeName pscustomobject
		    $PrevValue | Add-Member -MemberType NoteProperty -Name PrevValue -Value $CurrentVal
		    $PrevValue | Add-Member -MemberType NoteProperty -Name Timestamp -Value (Get-Date)
		    $PrevValue | Add-Member -MemberType NoteProperty -Name OutPutFile -Value $OutputFile
		    $PrevValue | Add-Member -MemberType NoteProperty -Name RefreshTime -Value $refreshtimeHTML
		    $tempvar | Add-Member -MemberType NoteProperty -Name $varName -Value $PrevValue
		    Set-Variable -Name HTMLArch -Value $tempvar -Scope global
		    Remove-VAriable tempvar
		    Remove-VAriable PrevValue
	
		    #-- write the HTML file
		    if (!(Test-FileLock $HTMLArch.$varname.outputfile)) {
		    $CurrentVal | ConvertTo-Html -Head $HTMLHeader | out-File $HTMLArch.$varname.OutPutFile -ErrorAction SilentlyContinue 
		    }
		    }
	    else { #-- archive object contains info about variable, so let's compare
		    $delay=(Get-Date) - $HTMLArch.$varname.timestamp
		    if(($delay.seconds -ge $HTMLArch.$varname.RefreshTime) -or $force) { #-- only compare if we supposed to
			    if ($noRefresh -eq $false) {
				    $HTMLHeader= '<meta http-equiv="refresh" content="'+$HTMLArch.$varname.RefreshTime+'">'}
			    $HTMLHeader= $HTMLHeader+ '	<META HTTP-EQUIV="Pragma" CONTENT="no-cache">
					    <META HTTP-EQUIV="Expires" CONTENT="-1">'	
			    $diff=Compare-Object ($CurrentVal|ConvertTo-Csv -NoTypeInformation ) $HTMLArch.$varname.PrevValue #-- get differences between actual and previous value
			    if ($diff) { #-- there is a difference, so let's process it to HTML format
				    $deel=@() #-- build array of differences
				    $deel +=$HTMLArch.$varname.PrevValue[0] #-- set array header
				    $diff| ?{$_.SideIndicator -like "<="}  | %{$deel += $_.Inputobject} #-- add only the new values to the array
				    $deel=$deel|ConvertFrom-Csv #-- convert it to csv format
				    $deelIntro='<p><b>Tijdstip laatst wijziging: '+(get-date)+'</b></p>' #-- Line above html table with differences
				    $deelFull='<p><b>Volledige tabel:</b></p>' #-- line above full html table 
				    if (!(Test-FileLock $HTMLArch.$varname.OutPutFile)) { #-- html file is not in use / locked
					    #-- write a new HTML file
					    $CurrentVal | ConvertTo-Html -Head $HTMLHeader -preContent ($deelIntro+($deel|ConvertTo-Html -Fragment )+$deelFull)| out-File $HTMLArch.$varname.OutPutFile -ErrorAction SilentlyContinue 
					    $HTMLArch.$varname.Timestamp = get-date #-- store a new timestamp in the archive object
					    $HTMLArch.$varname.PrevValue=$CurrentVal|convertto-csv -NoTypeInformation 	 #-- store the current value of the variable as the previous
					    }
				    }
			    }
		    }
    }

    function add-QueueProps {
	    [CmdletBinding()]
	    Param(
		    [string]$ArrayName,
		    [string]$FirstTask
	    )

	    $validObject=$false
	    if (Test-Path variable:$ArrayName) { #-- The given list exists
		    if (((Get-Variable -Scope script -Name $ArrayName -ValueOnly).gettype().basetype.name) -like "Array") { 
			    #-- the list exists as an array
			    $validObject=$true
			    }
		    }
		
	    if ($validObject) {
		    $tmpDate = get-date
		    $tmpobj = Get-Variable -Scope script -Name $ArrayName -ValueOnly 
		    $tmpobj | Add-Member -MemberType NoteProperty -Name Queue -Value $FirstTask #-- The que where this relations recides
		    $tmpobj | Add-Member -MemberType NoteProperty -Name keyID -Value "" #-- Que Item ID
		    $tmpobj | Add-Member -MemberType NoteProperty -Name QueueStatus -Value "Wait" #-- Que status of relation
		    $tmpobj | Add-Member -MemberType NoteProperty -Name QueueReason -Value "" #-- Reason of queue status
		    $tmpobj | Add-Member -MemberType NoteProperty -Name QueueStamp -Value $tmpDate #-- Timestamp	
		    #-- initialize the keyID property
		    $Index=0
		    $tmpobj | % {
			    $_.keyID = $index
			    $Index ++
		    }
		    Set-Variable -Name $Arrayname -Value $tmpobj -Scope script
		    Remove-Variable tmpobj
		    Remove-Variable index
	    }
    }

    function invoke-task {
	    [CmdletBinding()]
	    param(
		    [Parameter(HelpMessage="Name of the Itemlist to proces")]
		    [string]$ListName,
		    [Parameter(HelpMessage="Queue name of the task")]
		    [string]$Taskname,
		    [Parameter(HelpMessage="Scriptblock to execute while in Wait status. Scriptblock should return False (Starting task failed) or True (task started)")]
		    [scriptblock]$WaitCode={},
		    [Parameter(HelpMessage="Scriptblock to execute while in Busy status. Scriptblock should return False (Task is still busy) or True (Task is done)")]
		    [scriptblock]$BusyCode={},
		    [Parameter(HelpMessage="The name of the next task queue to enter when the current status is Done. When no name is given the queue finish is default.")]
		    [string]$NextTask="Finish"
	    )
			
	    #-- check if Listname is an array and has queue properties
	    $validObject=$false
	    if (Test-Path variable:$ListName) { #-- The given list exists
		    if (((Get-Variable -Scope script -Name $ListName -ValueOnly).gettype().basetype.name) -like "Array") { 
			    #-- the list exists as an array
			    $QueuePropertiesValid=$true
			    #-- check if the list has all the Queue properties
			    (Get-Variable -Scope script -Name $ListName -ValueOnly) | gm -MemberType NoteProperty |
				    select name | ? {($_ -like "Queue*") -or ($_ -like "keyID")} | %{
					    $QueuePropertiesValid= $QueuePropertiesValid -and (($_.name -like "Queue")  -or
																	    ($_.name -like "QueueReason") -or ($_.name -like "QueueStamp") -or
																	    ($_.name -like "QueueStatus") -or ($_.name -like "keyID"))
				    }
			    $validObject=$QueuePropertiesValid
			    }
		    }
	
	    #-- run task flow
	    if ($validObject) {
		    #-- filter the List into the given listname
		    [array]$Queue = (Get-Variable -Scope script -Name $ListName -ValueOnly )| ?{$_.Queue -like $TaskName}
		    if ($Queue.count -gt 0) { #-- There are items in the queue
			    $Queue |? {$_.QueueStatus -notlike "Failed"} |%{ #-- ignore failed items, proces the rest
				    remove-variable CodeResult -ErrorAction SilentlyContinue #-- remove $CodeResult variable
				    $QueueItem = $_

                    switch ($QueueItem.QueueStatus) {
                        #-- walk through each possible status for the task
                        "Wait"  {
                            #-- task is new in queue and waiting to start
                            if ($WaitCode -ne $null) {
                                #-- scriptblock for $waitcode found, start task
						        set-QueueStatus -item $QueueItem -State "Start" #-- mark it as being started
                      
                            } else {
                                #-- no scriptblock for $waitcode found, task failed
                                set-queuestatus -Item $queueItem -State "Failed" -Reason "Geen tmpWaitCode scriptblock gevonden voor task $taskname." 
                                break #-- exit switch
                            }  
                        }
                        "Start" {
                            #-- start task
						    & $WaitCode | out-null #-- execute scriptblock $WaitCode
						    if ($CodeResult -eq $true) {
                                #-- tmpWaitCode executed succesfully, set status to Busy
							    set-QueueStatus -item $QueueItem -State "Busy"  
                                }
						    elseif ($CodeResult -eq $false) {
                                #-- executing of $waitcode failed
                                set-QueueStatus -item $QueueItem -State "Failed" -Reason "Starten van task $Taskname is mislukt." 
                                break #-- exit switch
                                }
						    elseif ($CodeResult -eq $null) {
                                #-- No result from $waitcode scriptblock  
							    set-QueueStatus -item $QueueItem -State "Delayed" -Reason "Starten van task $Taskname is vertraagd." 
                                }
                            }
                        "Busy" {
                            #-- validate task execution, run validation code
					        & $BusyCode | out-null
                            #-- validate result of scriptblock
					        if ($CodeResult ) {
                                #-- Busy scriptblock returned $true, meaning task succesfully executed
						        set-QueueStatus -item $QueueItem -state "Done"
					            } 
                            elseif ($codeResult -eq $false ) {
                                #-- Busy scriptblock returned $false meaning validating $task execution failed
                                set-QueueStatus -Item $Queueitem -State "Failed" -Reason ("Validatie / busy scriptblock van task $taskname voor "+ $queueitem.queue + " is negatief.")
                                break #-- exit switch
                                }
                            }
                        "Done" {
                            #-- task executed succesfully and is done, move it to the next queue
					        if ($NextTask -like "Finish") { #-- when next task is Finish, the item is done, so the we give it the status Done
					            set-QueueStatus -item $QueueItem -State "Done" -NextQueue $NextTask}
					        else {
					            set-QueueStatus -item $QueueItem -State "Wait" -NextQueue $NextTask}
                            break #-- task is done and item is placed in next queue
                            }
                        "Delayed" {
                            #-- set status to Wait
					        set-QueueStatus -item $QueueItem -State "Wait" #-- mark it as being started
					        $log.verbose("Task ("+$QueueItem.Queue+") status voor "+ $QueueItem.queue + " wordt opnieuw op wait gezet.")
                            }
                        "Skipped" {
                            #-- Move item to Done phase
					        set-QueueStatus -item $QueueItem -State "Done"
                            break #-- exit switch
                            }
                        Default {
                            #-- unknown phase / status
					        set-QueueStatus -item $QueueItem -State "Failed" -Reason ("Onbekende Queue status ("+$QueueItem.QueueStatus+ ") gevonden.")
                            }
                    }

				    #-- update the Queue properties of this item in the main list
				    $($listname) | ? {$_.keyID -eq $QueueItem.keyID} | %{
					    $_.QueueReason = $QueueItem.QueueReason
					    $_.QueueStatus = $QueueItem.QueueStatus
					    $_.Queue = $QueueItem.Queue
					    $_.QueueStamp = $QueueItem.Queuetamp
					    }
                    #-- update HTML status page
				    Update-toHTMLStatus $ListName
				    } #-- end of process item	
			    } #-- end of task run
        } else {
            $log.verbose("task has invalid properties, cannot proces")
        }
    } #-- end of function
    
    function set-QueueStatus { #-- change the queue properties
	    [CmdletBinding()]
	    param (
		    [Parameter(Mandatory=$True,helpmessage="Object with Queue properties to edit")]
		    $Item,
		    [Parameter(HelpMessage="Name of the next queue.")]
		    [string]$NextQueue,
		    [Parameter(Mandatory=$true,HelpMessage="New queue state of the object")]
		    [ValidateSet("","Wait","Start","Busy","Done","Failed","Skipped","Delayed")]
		    [string]$State="Wait",
		    [Parameter(HelpMessage="Reason of queue state, used if Queue state is Failed.")]
		    [string]$Reason="" #-- when no reason is given, the reason is cleared
		    )
	    #-- Change the Queue properties
	    $Item.QueueStamp = Get-Date #-- enter a new timestamp
	    $Item.QueueStatus = $State
	    $Item.QueueReason = $reason 
	    if ($NextQueue.length -gt 0) { $Item.Queue = $NextQueue }
	    } #-- end of private function

#endregion
  
    $taskParameters=@{}
    $CSVTable=import-tasktable -CSVFile $P.CSVfile -refHeader $p.refHeader -csvDelimiter $p.CSVDelimiter
    # build task parameter hash table
    $CSVTable | %{$taskParameters.add($_.servername,$_)}
    Remove-Variable -Name TaskTable -Force -ErrorAction SilentlyContinue
    # build Array for for task status
    [array]$TaskTable=$taskParameters.GetEnumerator() | select -ExpandProperty value | select servername
    $log.msg("Importeren van CSV is gelukt. "+ $TaskTable.Count + " regels geïmporteerd.")
    # add Queue properties
    add-QueueProps -ArrayName TaskTable -FirstTask Init
}

Process{
#-- note: area to write script code.....
    import-PowerCLI
    $log.msg("PowerCLI loaded")

    # connect to vCenter, assuming to use credentials from user that is running powershell
    if (Connect-VIServer -Server $P.vCenter) { 
        $log.msg("Connected with vCenter "+ $P.vcenter)
    }else {
        $log.msg("Couldn't connect to vcenter "+ $p.vCenter)
      #  exit-script  #-- debug
    }

    # remove VMs from tasktable that already exist on cluster
    if (!(get-cluster -Name $P.Cluster -ErrorAction SilentlyContinue)) {
        #-- Cluster bestaat niet
        $log.warning("Cluster " + $P.cluster + " niet gevonden.")
        exit-script
    }
    $ClusterVMs=get-cluster $P.Cluster | Get-VM | select -ExpandProperty name
    $tmp_hashTable=@{} # build hashtable from tasktable
    $tasktable | %{$tmp_hashTable.add($_.servername,$_)}
    $ExistingVMs= Compare-Object -ReferenceObject $ClusterVMs -DifferenceObject ($tmp_hashTable.GetEnumerator() | select -ExpandProperty name) -ExcludeDifferent -IncludeEqual | select  -ExpandProperty  inputobject 
    $existingVMs | %{
        $vm=$_
        $log.msg("Remove VM $_ from tasktable, it exists already in the cluster")
        $tmp_hashTable.Remove($_)} # remove VMs from hashtable that already exists in the cluster
    #convert hashtable back to tasktable as an array
    Remove-Variable tasktable
    [array]$tasktable=$tmp_hashTable.GetEnumerator() | select -ExpandProperty value
    if ($TaskTable.count -eq 0) {
        $log.warning("Geen VMs om uit te rollen.")
        $finished_normal=$true
        exit-script
    }
    #-- build hashtable to store temporary data
    $tasktable_tempdata=@{}
    $TaskTable | %{
        $tasktable_tempdata.add($_.servername,"")
        }

  
    if ($p.SelectFirstHost) {
        $vmhost = get-cluster $p.cluster | get-vmhost | select -first 1
    } else {
        $vmhost=get-cluster $p.cluster |  get-vmhost |Out-GridView -Title "Select vsphere ESXi host for deployment." -OutputMode Single
    }
    if ($vmhost) {
        $log.msg($vmhost.name + " geselecteerd om VMs uit te rollen.")
    }else{
        $log.warning("Geen vSphere host kunnen selecteren.")
        exit-script
    }

    $Loopcounter=0
    $exitloop=$false
    Update-toHTMLStatus -varName tasktable
    $log.verbose("HTML report created in "+ $HTMLArch.tasktable.outputfile)
    Start-Process -WindowStyle Normal -FilePath $HTMLArch.tasktable.OutPutFile
    Do {
    	$Loopcounter ++
        Write-Verbose "----- LOOP : $Loopcounter "
        #-- TASK: INIT
	    $tmpWaitCode = {
            #-- let the invoke-task function know that code has run succesfully
            $log.verbose($queueitem.servername + ": Task - Initiate job")
		    Set-Variable -Name CodeResult -Scope script -Value $True #-- Wait scriptblock finished succesfully
            }
        $tmpBusyCode ={
            #-- nothing to check
		    Set-Variable -Name CodeResult -Scope script -Value $True #-- busy scriptblock finished succesfully
        }
        invoke-task -ListName "tasktable" -Taskname "Init" -NextTask "CloneVM" -BusyCode $tmpBusyCode -WaitCode $tmpWaitCode

        #-- TASK: Clone VM 	
	    $tmpWaitCode = { 
            $log.verbose($queueitem.servername + ": Task - CloneVM")
            #-- configure OS Customization Specification
            $vm=$taskparameters.$($queueitem.servername)
            $log.verbose($queueitem.servername + ": configurre OS Customization Spec")
            $specs = Get-OSCustomizationSpec $vm.OSCustomizationSpec
            $specs | Get-OSCustomizationNicMapping | Set-OSCustomizationNicMapping -IpMode UseStaticIp -IpAddress $vm.ip -SubnetMask $p.subnetmask -DefaultGateway $p.gateway -DNS $p.dns | Out-Null
            #-- deploy new VM from Template and store TASK id
            $log.verbose($queueitem.servername + ": deploy VM")
            $tasktable_tempdata.$($vm.servername)=(  new-vm -vmhost $vmhost -name $vm.servername -template $vm.template -datastore $vm.datastore -OSCustomizationSpec $specs -RunAsync).id
            
            #-- let the invoke-task function know that code has run succesfully
		    Set-Variable -Name CodeResult -Scope script -Value $True
        }
        $tmpBusyCode = {

            switch (get-task -id $tasktable_tempdata.$($queueitem.servername) | select -ExpandProperty state ) {
                "Success" {
                    #-- Deploying new VM was succesfull
                    $log.msg($queueitem.servername + " : Deployment taak succesvol uitgevoerd.")
                    $answer=$true
                    $tasktable_tempdata.$($queueitem.servername)=""
                    }
                "Error" {
                    #-- Deployment off new VM was unsuccesfull
                    $log.msg($queueitem.servername + " : Deployment taak mislukt.")
                    $answer=$false
                    $tasktable_tempdata.$($queueitem.servername)=""
                    }
                "unknown" {
                    #-- Deployment task has status unknown
                    $log.msg($queueitem.servername + " : onbekende taak.")
                    $answer=$false
                    $tasktable_tempdata.$($queueitem.servername)=""
                    }
            }
		    Set-Variable -Name CodeResult -Scope script -Value $answer
        }
        invoke-task -ListName "tasktable" -Taskname "CloneVM" -NextTask "ConfigHW" -BusyCode $tmpBusyCode -WaitCode $tmpWaitCode

        #-- TASK: Modify VM hardware 	
	    $tmpWaitCode = {
            $log.verbose($queueitem.servername + ": Task - config HW")
            $HWParams=$taskparameters.($queueitem.servername)
            #-- configure disks
            $disks=($hwparams | gm -name "Hard disk*")
            if ($disks.count -gt 0) {
                $disks | %{
                    #-- walk through each disk in job
                    $disk=$_.name
                    $diskinKB=[int]$hwparams.($disk) * 1048576
                    $harddisk=Get-HardDisk -vm $queueitem.servername | ?{ $_.name -ilike $disk}

                    if ($harddisk) {
                        #-- configure harddisk size of existing harddisk
                        $log.verbose($queueitem.servername + ": " + $harddisk.name + " gevonden.") 
                        if ($harddisk.CapacityKB -lt $diskinKB ) {
                            #-- desired disk size is greater then actual disk size
                            $log.verbose($queueitem.servername + ": " +$disk + " is vergroot naar " + $hwparams.($disk) + "[GB]")
                            Set-HardDisk -HardDisk $harddisk  -CapacityKB $diskinKB -Confirm:$false
                        } else {
                            #-- desired disk size is less then actual disk size, can't adjust size
                            $log.warning($queueitem.servername + ": " +$disk + " is groter dan gewenste groote van "+ $hwparams.($disk) + "[GB]")
                        }
                    } elseif ($diskinKB -gt 0) {
                        #-- disk doesn't exist, so let's create it, thinprovisioned.
                        $log.verbose($queueitem.servername + ": " + $harddisk.name + " niet gevonden.")
                        New-HardDisk -CapacityKB $diskinKB -VM $queueitem.servername -StorageFormat Thin
                    }
                }
            } else {
                $log.msg($queueitem.servername + ": " +"Geen disken gevonden.")
            }
            #-- aanpassen van de andere HW
            $log.verbose($queueitem.servername + ": aanpassen HW")
            Set-VM -vm $HWParams.servername -NumCpu $HWParams.vcpu -MemoryGB $HWParams.memory  -Confirm:$false -Notes $HWParams.notes

            #-- let the invoke-task function now that code has run succesfully
		    Set-Variable -Name CodeResult -Scope script -Value $True
        }
        $tmpBusyCode = {
        
            $HWParams=$taskparameters.($queueitem.servername)
            $vm=get-vm $Queueitem.servername
            $vmHW_OK=$true
            if ($vm.MemoryGB -ne $HWParams.memory) {
                $log.warning($queueitem.servername + ": Memory VM ("+ $vm.MemoryGB +  " [GB]) <> opdracht (" + $HWParams.memory + " [GB])")
                $vmHW_OK=$false
            }
            if ($vm.NumCpu -ne $HWParams.vcpu) {
                $log.warning($queueitem.servername + ": vCPU count VM ("+ $vm.numcpu +  ") <> opdracht (" + $HWParams.vcpu + ")")
                $vmHW_OK=$false
            }
            
            #-- Check vmdk size
            $disks=($hwparams | gm -name "Hard disk*")
            $diskcount=0
            $disks | %{
                $diskname=$_.name
                if ($hwparams.($diskname) -gt 0) {
                    $diskcount++
                    }
                }
            if ($diskcount -ne (($vm | get-harddisk).count)) {
                #-- check if number of vmdks are correct
                $log.warning($queueitem.servername + ": aantal HDD niet correct ("+ (($vm | get-harddisk).count) +  ") <> opdracht (" + $disks.count + ")")
                $vmHW_OK=$false
            }
            
            $answer=$vmHW_OK
            
		    Set-Variable -Name CodeResult -Scope script -Value $answer 
        }
        invoke-task -ListName "tasktable" -Taskname "ConfigHW" -NextTask "CustomizeOS" -BusyCode $tmpBusyCode -WaitCode $tmpWaitCode


        #-- TASK: CustomizeOS	
	    $tmpWaitCode = {
            $log.verbose($queueitem.servername + ": Task - CustomizeOS")
            $log.verbose($queueitem.servername + ": Start VM")
            #-- start VM
            $id=get-vm -Name $queueitem.servername | Start-VM -RunAsync
            #-- store task ID
            $tasktable_tempdata.$($queueitem.servername)=$id
		    Set-Variable -Name CodeResult -Scope script -Value $True
        }
        $tmpBusyCode = {
            #-- waiting for the event 'Customization of VM ******** succeeded'
            #-- note time of when VM start event was triggered
            $TimeStarted=get-vievent -Entity $queueitem.servername | ?{$_.fullformattedmessage -ilike "Task: Power On virtual machine"} | sort createdtime | select -ExpandProperty CreatedTime -last 1
            if (((get-date) - $TimeStarted).Minutes -gt $p.TO_OSCustomization) {
                #-- Customization off OS did not finish in time.
                $log.warning($queueitem.servername + ": "+  $P.TO_OSCustomization +  "[min] gewacht op OS customization.")
                $answer=$false
            }else{
                #--Check events for customization events
                switch -Regex (get-vievent -Entity $queueitem.servername | select -ExpandProperty FullFormattedMessage ) {
                    "^Customization of.*succeeded." {
                        #-- customization is finished, task finished
                        if ($tasktable_tempdata.$($queueitem.servername) -eq "CustOS_Started") {$log.msg($queueitem.servername + ": OS customazation finished.")}
                        $tasktable_tempdata.$($queueitem.servername)="CustOS_Finished"
                        $CustFinished=get-vievent -Entity $queueitem.servername | ?{$_.fullformattedmessage -imatch "^Customization of.*succeeded."} | select -ExpandProperty createdtime
                        if  (((get-date)-$CustFinished ).minutes -gt $P.TO_waitAfterCust) {
                            $log.verbose($queueitem.servername + ": waited " + $P.TO_waitAfterCust + "[min] before shutdown of VM. OS Customization is finished.")
                            $answer=$true
                            $tasktable_tempdata.($queueitem.servername)=""
                        }
                        break
                        }
                    "^Started customization of VM.*" {
                        if ($tasktable_tempdata.($queueitem.servername) -inotlike "CustOS_Started") {
                            $event=get-vievent -Entity $queueitem.servername | ?{$_.FullFormattedMessage -imatch "^Started customization of VM.*"} | select -First 1
                            $log.msg($queueitem.servername + ": OS customization is gestart om "+ $event.createdTime)
                            $tasktable_tempdata.($queueitem.servername)="CustOS_Started"
                            Set-Variable  -name OSCustomFinished -Value $false -Scope script
                        }
                        break
                    }
                }

            }
		    Set-Variable -Name CodeResult -Scope script -Value $answer
        }
        if ($P.ShutDownAfterCust) {
            invoke-task -ListName "tasktable" -Taskname "CustomizeOS" -NextTask "ShutdownVM" -BusyCode $tmpBusyCode -WaitCode $tmpWaitCode

            #-- TASK: Shutdown VM 	
	        $tmpWaitCode = {
                $log.verbose($queueitem.servername + ": Task - Shutdown VM")
                $vm = get-vm $queueitem.servername
                if ($vm.extensiondata.guest.toolsstatus -imatch "toolsNotInstalled|toolsNotRunning") {
                    #-- VMware tools not active ==> powering off VM
                    $log.msg($queueitem.servername + ": Powering Off VM")
                    Stop-VM -VM $vm -RunAsync -Confirm:$false
                } else {
                    $log.msg($queueitem.servername + ": Shutdown Guest OS")
                    #-- VMware tools is running ==> shutdown Guest OS
                    Stop-VMGuest -VM $vm -Confirm:$false
                }
                #-- let the invoke-task function now that code has run succesfully
		        Set-Variable -Name CodeResult -Scope script -Value $True
            }
            $tmpBusyCode = {
                $event=Get-VIEvent -Entity $queueitem.servername | ?{$_.FullFormattedMessage -imatch "Task: Initiate guest OS shutdown|Task: Power Off virtual machine"} | Sort-Object -Property Createdtime | select -first 1
            #    $event=Get-VIEvent -Entity $queueitem.servername | ?{$_.FullFormattedMessage -imatch "Task: VirtualMachine.shutdownGuest|Task: VirtualMachine.powerOff"} | Sort-Object -Property Createdtime | select -first 1
                if ($event) {
                    if (((get-date) - $event.createdtime).minutes -gt $p.TO_ShutdownPeriod) {
                        #-- originele shutdown duurt te lang
                        $log.warning($queueitem.servername + " : Shutdown van VM duurt te lang. Hernieuwde poging")
                        $vm = get-vm $queueitem.servername
                        if ($vm.extensiondata.guest.toolsstatus -imatch "toolsNotInstalled|toolsNotRunning"){
                            stop-vm -vm $vm -Confirm:$false -RunAsync
                        } else {
                            Stop-VMGuest -vm $vm -Confirm:$false
                        }
                        $answer=$false
                    } elseif ((get-vm $queueitem.servername).PowerState -eq "PoweredOff") {
                        #-- VM is powered Off
                        $answer=$true
                    }
                }
		        Set-Variable -Name CodeResult -Scope script -Value $answer 
            }
            invoke-task -ListName "tasktable" -Taskname "ShutdownVM" -NextTask "Finished" -BusyCode $tmpBusyCode -WaitCode $tmpWaitCode
        }
        else {
            invoke-task -ListName "tasktable" -Taskname "CustomizeOS" -NextTask "Finished" -BusyCode $tmpBusyCode -WaitCode $tmpWaitCode

        }



      #-- loop accounting
	$RelationsFailed =($tasktable | ? {$_.QueueStatus -like "Failed"} | Measure-Object).count
	$RelationsFinished =( $tasktable | ? {$_.Queue -like "Finished"} | Measure-Object).count 
	$RelationsSkipped = ($tasktable | ? {$_.QueueStatus -like "Skipped"} | Measure-Object).count
	$Duration = (get-date) - $ts_start 
	Start-Sleep -Seconds $p.idletime
	$exitLoop = (($RelationsFailed + $RelationsFinished + $RelationsSkipped) -eq $tasktable.Count ) -or ($Duration.Hour -gt $p.MaxrunningHours)
    } until ($exitloop)


    #-- Evaluation of routine
    if ($Duration.days -gt $p.MaxrunningHours) {
	    $log.error("Uitrollen van VMs is mislukt, we zijn meer dan "+ $p.MaxrunningHours + " uur druk geweest.")
	    } 	
      elseif (($FailedRelations.count -gt 0 ) -or ($FailedPrecheck -gt 0)) {
	    $log.warning("Uitrollen van VMs is gedeeltelijk gelukt, niet alle VMs zijn uitgerold. (check "+$HTMLArch.tasktable.OutPutFile +")")
	    }
      else {
        $log.msg("Uitrollen VMs is gelukt. (check "+$HTMLArch.tasktable.OutPutFile+")")
	    }

    #-- final report update
    Update-toHTMLStatus -varname tasktable -force -norefresh
}

End{
    #-- we made it, exit script.
    $finished_normal=$true
    exit-script
}
