#
#
##################################################################
#                                                                #
#                     Find User Logon Hostname                   #
#		                Gordon Merryweather                      #
#                                                                #
##################################################################
#
# Requires Active Directory addons for Powershell
#
#	v2.00   13/11/19	Rewriting script to use forms
#   v3.05   21/01/20    DC search now uses PS jobs for concurrent searching
#   v3.10               Bug fixes and better logging info
#                       Add ability to change scan timeout
#   v3.12               Add listview column sorting
#                       Remove culture change from main script body
#   v3.13   22/01/20    Optimise code
#   v3.14   23/01/20    Load dll from module path instead of using namespace
#
##################################################################
#
# Requires access to the Domain Controller security logs to view lockout events.
# To amend group policy for the domain so that logs are accessible by user/group:
# Add user/group to the domain "BUILTIN\Event Log Readers" group
# Add the "BUILTIN\Event Log Readers" group to the following registry key using group policy
# Domain Controllers Default Policy > Group Policy Object Editor: Computer Configuration > Policies > Windows Settings > Security Settings.
# Add entry for: 
# HKLM\System\CurrentControlSet\Services\Eventlog\Security
# This key only
# Query Value, Enumerate Subkeys, Notify, Read Control
#
###############################################################################
#
# Amend as required to set up DCs unchecked by default
#
$DCExclude = @('AZUREDC01','DC30')
#
###############################################################################
$Version = 'v3.14'
#
#
Try {
    Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop
}
Catch {
    $_
    Pause
    Break
}
#
#
#Region Base64Image
# Branding image in Base64 format
$Image = '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'
# Utility icon in Base64 format
$IconBase64 = 'iVBORw0KGgoAAAANSUhEUgAAAEgAAABICAYAAABV7bNHAAAEG0lEQVR4nO1ba5XzIBC9EiIBCZWAhEpAQiXgoBIioRIioRIiIRL6/aA5u5sl84CBdPv1njM/GYabefEI8MEHH7wRBgAnAGcAAYB/ijvKoCMxIC3+CuAOY
AHwYGQGcEMib+htcA8MSN5xg4wQTm4AIt7Aw1ZiZtSTsifXbqsxhkcKoVbEfJcFKfz+BAakEOhBzFbuSMn+ZXFC23CSyrn1QkvgUZ+AFyQvsCD50nS1SlygJ2dGSrAnpGqUK98OyRsuKMtnN9tlliFATs4CYMTvPDEgkeGRCPHIl/ABiSwNS
bFyfVU4QU7OhJ/ErA0j1yzeka9QV+G8h+WkATK3XzIGlibzrR4ntOGBA6qbpJTf8TtUNF6Xk1Boy1K5XhXOAoMm/E68A2wqVM4bomBcrFq1AhNjyB35qqTJG5TMO3ZxnrSgw/4tCIzIfeEBNhtVKtQAPieNRasWQhIiexVDEpYa2VuoxEanX
rkQ3CKpxsx6f0Yl3cCMbeZF1CL3QmsF91VLhDo8o+ZrUtG4HMKdy1iT80BqNPcQmLHmfREXXpSxAzO2VLgOmfIi84M2KrzuzFhHjK2RwMw7EmPNw6zmazhibI1wRxqc15teAFD5h3N1xxjayoO40DbLQ46ZyFUaWiqSXTrl+V4wXoQTY6gEl
l20xgMmYrzZqaMnJpmFOihDS2SBLIeMhI4otJ1FICbhKtiKSOgoEelxKrVBHoU6WFDVQFourfNQFM5LeZBZL0TlIE0/MRN6tOKEc1L9W1TYToL7+tJ+IjB6rMMLoI8/gkIPC8pgaT9hdaLoFXbX9G8qUBNpymUk9Fh7j2d0OYUuFlSy017Ql
T5q4I5UtoiELmn1FSMQk2m/hmN0WXgqQPdeo1IXCy5RR4UuD30u0j5x4TaqGl1iUKEhKfee0WFJFHf66QQ61ODuxfdCwMP+MRVFlGfGNnvUIOmGvydRDz0x2sP9LVGSK3FfzQSByEw+o4yY7wstubtfx3OXk+bVawurZi9H6naeyXieBzq99
AjGRs/I3+Nb36V1fVBl7UXb+/zRWL/0/MgMzngBD3xVQd9Ad7QmQAKvNFITZpOh7tWDDnkirH0zuCfb5NnioH8l6YT8+6VmGCsNH3f0Wr8IWUmakffapqh5HLUgVZjxqeeK9IV7/MrQlaQWX7yHdCWp9pFmbfjEwvm7kgTYX/NwMuFrh176k
bqT5GDf8OWIyW0f/gxJq7FjocF7oTSB7mtq/jw6hKQVZ6Tw0xq/VroA2WFX7T7uUJJWOHz9wBKQiBuRyvzlKR5lHbD0V4mXJ6klrEh6a1iQFHsb3RsWJL11qAH1JPnuFh+AGpJCf3OPQSlJL/kndStoSeryG9WrQUNSPMbE4yEh6Yb/oIJxi
MiH1QUfcn5g3fKc8CHmgw+OxD/4AsoKHnresAAAAABJRU5ErkJggg=='
#EndRegion Base64Image
# Convert back to icon file for forms
Function Get-ImgStreamFromB64 ($B64Img) {
    $Bytes = [Convert]::FromBase64String($B64Img)
    $stream = New-Object IO.MemoryStream($Bytes, 0, $Bytes.Length)
    $stream.Write($Bytes, 0, $Bytes.Length);
    Return $stream
}
#
$MyImg = New-Object System.Drawing.Bitmap -Argument (Get-ImgStreamFromB64 $Image)
$MyIcon = [System.Drawing.Icon]::FromHandle((New-Object System.Drawing.Bitmap -Argument (Get-ImgStreamFromB64 $IconBase64)).GetHIcon())
#
# When invoked, the following uses the credentials of the script to search, rather than the credentials of who runs the script
# This ensures that when compiled as an executable to run under the another credential it uses that rather than the current user
$GetUserDetail = { Get-ADUser -LDAPFilter "(anr=$args)" | Select-Object Name , SamAccountName }
#
# Timeout/sleep to wait for jobs to finish
$Script:TimeOut = 150
[int]$SleepTime = 1
#
# Set up functions
#
Function SortListView {
    Param(
        [System.Windows.Forms.ListView]$sender,
        $column
    )
    $temp = $sender.Items | Foreach-Object { $_ }
    $Script:SortingDescending = !$Script:SortingDescending
    $sender.Items.Clear()
    $sender.ShowGroups = $false
    $sender.Sorting = 'none'
    $sender.Items.AddRange(($temp | Sort-Object -Descending:$script:SortingDescending -Property @{ Expression={ $_.SubItems[$column].Text } }))
}
#
Function Get-UserDetail {
    param(
    [Parameter(Mandatory=$true)]
    [string]$NameOrUID
    )
    $UADObject = {Invoke-Command -ScriptBlock $GetUserDetail -ArgumentList $NameOrUID}.Invoke()
    If ($UADObject) {
        Return $UADObject
    }
    Else {
        Return "Invalid name"
    }
}
#
Function Get-LoggedOnUser {
	param(
	    [CmdletBinding()] 
	    [Parameter(ValueFromPipeline=$true,
        ValueFromPipelineByPropertyName=$true)]
	    [string[]]$ComputerName = 'localhost'
	)
	begin {
		$ErrorActionPreference = 'Stop'
	}
	process {
    	foreach ($Computer in $ComputerName) {
    	    try {
        	    quser /server:$Computer 2>&1 | Select-Object -Skip 1 | ForEach-Object {
            	    $CurrentLine = $_.Trim() -Replace '\s+',' ' -Split '\s'
            	    $HashProps = @{
            	        UserName = $CurrentLine[0]
            	        ComputerName = $Computer
            	    }
					# If session is disconnected different fields will be selected
					if ($CurrentLine[2] -eq 'Disc') {
						$HashProps.SessionName = $null
						$HashProps.Id = $CurrentLine[1]
						$HashProps.State = $CurrentLine[2]
						$HashProps.IdleTime = $CurrentLine[3]
						$HashProps.LogonTime = $CurrentLine[4..6] -join ' '
						$HashProps.LogonTime = $CurrentLine[4..($CurrentLine.GetUpperBound(0))] -join ' '
					}
					else {
						$HashProps.SessionName = $CurrentLine[1]
						$HashProps.Id = $CurrentLine[2]
						$HashProps.State = $CurrentLine[3]
						$HashProps.IdleTime = $CurrentLine[4]
						$HashProps.LogonTime = $CurrentLine[5..($CurrentLine.GetUpperBound(0))] -join ' '
					}
					New-Object -TypeName PSCustomObject -Property $HashProps | Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
				}
			}
			catch {
				New-Object -TypeName PSCustomObject -Property @{
				ComputerName = $Computer
				Error = $_.Exception.Message
				} | Select-Object -Property UserName,ComputerName,SessionName,Id,State,IdleTime,LogonTime,Error
			}
		}
	}
}
#
# End of functions
#
#Region FormElements
#
# Basic form setup
$form = New-Object System.Windows.Forms.Form
$form.Font = New-Object System.Drawing.Font("Segoe", 8)
$form.Text = "Find User Logon Locations - $Version"
$form.Size = '590,780'
$form.StartPosition = 'CenterScreen'
$form.MaximizeBox = $false
$form.Icon = $MyIcon
$form.FormBorderStyle = 'FixedSingle'
#
#Autoscaling settings
$form.AutoScale = $true
$form.AutoScaleMode = "Font"
$ASsize = New-Object System.Drawing.SizeF(7,15)
$form.AutoScaleDimensions = $ASsize
#
# Group for UID entry
$UIDEntryGrp = New-Object System.Windows.Forms.GroupBox
$UIDEntryGrp.Location = '10,10'
$UIDEntryGrp.Size = '310,45'
$UIDEntryGrp.Text = 'Enter user name/UID and click "Search"'
$UIDEntryGrp.Anchor = 'Top,Left'
# Entry box for UID
$UIDentry = New-Object System.Windows.Forms.Textbox
$UIDEntry.Location='10,15'
$UIDentry.Size = '200,20'
$UIDentry.TabStop = $true
$UIDentry.TabIndex = 1
# UID Search Button
$SearchButton = New-Object System.Windows.Forms.Button
$SearchButton.Location = '220,13'
$SearchButton.Size = '75,22'
$SearchButton.Text = 'Search'
$SearchButton.Anchor = 'Top,Left'
$SearchButton.TabIndex = 2
$SearchButton.TabStop = $true
#
# User list group
$UserListGrp = New-Object System.Windows.Forms.GroupBox
$UserListGrp.Location = '10,65'
$UserListGrp.Size = '310,110'
$UserListGrp.Text = 'Select User'
$UserListGrp.Anchor = 'Top,Left'
# List of Users/UIDs from search
$UIDlist = New-Object System.Windows.Forms.ListView
$UIDlist.View = [System.Windows.Forms.View]::Details
$UIDlist.Location = '10,15'
$UIDlist.Size = '290,85'
$UIDlist.Columns.Add('UID') | Out-Null
$UIDlist.Columns.Add('Name') | Out-Null
$UIDlist.MultiSelect = $false
$UIDlist.FullRowSelect = $true
$UIDlist.Add_ColumnClick({SortListView $this $_.Column})
$UIDlist.Anchor = 'Top,Left'
$UIDlist.TabIndex = 3
$UIDlist.TabStop = $true
#
#
$DASImage = New-Object System.Windows.Forms.PictureBox
$DASImage.Width = $MyImg.Width
$DASImage.Height = $MyImg.Height
$DASImage.Location = '327,10'
$DASImage.Image = $MyImg
$DASImage.Anchor = 'Top,Right'
#
# Current script user
$CurUserLbl = New-Object System.Windows.Forms.Label
$CurUserLbl.Location = '327,93'
$CurUserLbl.Size = '230,15'
$CurUserLbl.ForeColor = 'DarkGray'
$CurUserLbl.Anchor = 'Top,Left'
#
# Group for selected user
$SettingsGroupBox = New-Object System.Windows.Forms.GroupBox
$SettingsGroupBox.Location = '327,110'
$SettingsGroupBox.Size = '242,65'
$SettingsGroupBox.Text = 'Selected User'
$SettingsGroupBox.Anchor = 'Top,Left'
#
$labelName = New-Object System.Windows.Forms.Label
$labelName.Location = '10,20'
$labelName.Size = '40,15'
$labelName.Text = 'Name:'
#
$SettingName = New-Object System.Windows.Forms.Label
$SettingName.Location = '50,20'
$SettingName.Size = '180,20'
#
$labelUID = New-Object System.Windows.Forms.Label
$labelUID.Location = '10,40'
$labelUID.Size = '40,15'
$labelUID.Text = 'UID:'
#
$SettingUID = New-Object System.Windows.Forms.Label
$SettingUID.Location = '50,40'
$SettingUID.Size = '180,20'
#
# End of group
#
# DC list group
$DCListLbl = New-Object System.Windows.Forms.GroupBox
$DCListLbl.Location = '10,185'
$DCListLbl.Size = '560,210'
$DCListLbl.Text = 'Check/Uncheck DCs as required - multiple select allowed'
$DCListLbl.Anchor = 'Top,Left'
# List of Domain Controllers
$DCList = New-Object System.Windows.Forms.ListView
$DCList.View = 'Details'
$DCList.Location = '10,20'
$DCList.Size = '540,180'
$DCList.CheckBoxes = $true
$DCList.MultiSelect = $true
$DCList.FullRowSelect = $true
$DCList.Columns.Add('Name',120) | Out-Null
$DCList.Columns.Add('Site',210) | Out-Null
$DCList.Columns.Add('OperatingSystem',180) | Out-Null
$DCList.Add_ColumnClick({SortListView $this $_.Column})
$DCList.TabIndex = 4
$DCList.TabStop = $true
#
# Scan button label
$ScanBtnLbl = New-Object System.Windows.Forms.GroupBox
$ScanBtnLbl.Location = '10,405'
$ScanBtnLbl.Size = '560,50'
$ScanBtnLbl.Text = "Click 'Scan' to search DC logon events for this user"
$ScanBtnLbl.Anchor = 'Top,Left'
# Scan timeout label
$ScanTimeLbl = New-Object System.Windows.Forms.Label
$ScanTimeLbl.Location = '20,22'
$ScanTimeLbl.Size = '135,20'
$ScanTimeLbl.Text = 'Scan jobs timeout (secs):'
# Scan timeout value
$ScanTimeout = New-Object System.Windows.Forms.Textbox
$ScanTimeout.Location = '155,20'
$ScanTimeout.Size = '40,20'
$ScanTimeout.TextAlign = 'Right'
$ScanTimeout.Text = $TimeOut
$ScanTimeout.Enabled = $false
# Scan DCs button
$ScanButton = New-Object System.Windows.Forms.Button
$ScanButton.Location = '420,12'
$ScanButton.Size = '130,30'
$ScanButton.Text = 'Scan'
$ScanButton.Enabled = $false
$ScanButton.TabIndex = 5
$ScanButton.TabStop = $true
# Progress logging window
$ProgressBox = New-Object System.Windows.Forms.TextBox
$ProgressBox.Location = '10,465'
$ProgressBox.Size = '560,135'
$ProgressBox.Enabled = $true
$ProgressBox.Multiline = $true
$ProgressBox.ScrollBars = "Vertical"
$ProgressBox.ReadOnly = $true
$ProgressBox.Anchor = 'Top,Bottom,Left'
#
#
# List of sessions
$LogonList = New-Object System.Windows.Forms.ListView
$LogonList.View = 'Details'
$LogonList.Location = '10,610'
$LogonList.Size = '560,15'
$LogonList.Height = 120
$LogonList.FullRowSelect = $true
$LogonList.Columns.Add('UID',60) | Out-Null
$LogonList.Columns.Add('IPAddress',100) | Out-Null
$LogonList.Columns.Add('HostName',150) | Out-Null
$LogonList.Columns.Add('LogonTime',120) | Out-Null
$LogonList.Columns.Add('Status',100) | Out-Null
$LogonList.TabIndex = 6
$LogonList.TabStop =$true
# Add controls to form
$UIDEntryGrp.Controls.AddRange(@($UIDentry,$SearchButton))
$UserListGrp.Controls.Add($UIDlist)
$DCListLbl.Controls.Add($DCList)
$ScanBtnLbl.Controls.AddRange(@($ScanTimeLbl,$ScanTimeout,$ScanButton))
$SettingsGroupBox.Controls.AddRange(@($labelName,$SettingName,$labelUID,$SettingUID))
$form.Controls.AddRange(@($UIDEntryGrp,$UserListGrp,$SettingsGroupBox,$DASImage,$CurUserLbl,$DCListLbl,$ScanBtnLbl,$ProgressBox,$LogonList))
#
#EndRegion FormElements
#
# Search button pressed
$SearchButton.Add_Click({
    $UIDlist.Items.Clear()
    $ProgressBox.Text = $null
    $ProgressBox.AppendText("`r`nSearching...")
    $RequestedUID = $UIDentry.Text
    If ($RequestedUID) {
        $PossibleUserList = Get-UserDetail $RequestedUID
        If ($PossibleUserList -like '*invalid*') {
            $ProgressBox.AppendText("`r`nNo user matching $RequestedUID")
        }
        Else {
            $PossibleUserList | ForEach-Object {
                $UIDresult = New-Object System.Windows.Forms.ListViewItem($_.SamAccountName)
                $UIDresult.SubItems.Add($_.Name) | Out-Null
                $UIDlist.Items.Add($UIDresult) | Out-Null
            }
            $UIDlist.AutoResizeColumns([System.Windows.Forms.ColumnHeaderAutoResizeStyle]::ColumnContent)
        }
        $ProgressBox.AppendText("`r`nDone.")
    }
    Else {
        $ProgressBox.AppendText("`r`n* No entry in search box")
    }
})
#
# User entry is highlighted
$UIDlist.Add_SelectedIndexChanged({
    # Legacy Winforms behaviour causes an error unless a null check is made
    If($UIDlist.SelectedItems -ne $null) {
        $SettingUID.Text = $SettingName.Text = $null
        Try {
            $SettingUID.Text = $UIDlist.SelectedItems.SubItems[0].Text
            $SettingName.Text = $UIDlist.SelectedItems.SubItems[1].Text  
            #
            $ScanButton.Enabled = $true
            $ScanTimeout.Enabled = $true
        }
        Catch {
            $ProgressBox.AppendText("$_")
        }
    }
})
#
# Scan timeout changed
$ScanTimeout.Add_Leave({
    $Script:TimeOut = $ScanTimeout.Text
    $ProgressBox.AppendText("`r`nEvent log searches will time out at $TimeOut seconds")
})
#
# Scan button clicked
$ScanButton.Add_Click({
    $LogonList.Items.Clear()
    If(Get-Job) { 
        Get-Job | Remove-Job -Force 
    }
    $ScanButton.Enabled = $false
    $ScanTimeout.Enabled = $false
	$SearchButton.Enabled = $false
    # Retrieve most recent logon event for user on each DC
    $SessionList = @()
	$DCList.CheckedItems | ForEach-Object {
        $ProgressBox.AppendText("`r`nStarting event log search for" + $_.Text)
    # Start job for each DC
        Try {    
            $NewJob = Start-Job -Name $_.Text -ArgumentList $_.Text , $SettingUID.Text -ScriptBlock {
                Param($servername,$UID) 
                Function Set-Culture([System.Globalization.CultureInfo] $culture) {
                    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $culture
                    [System.Threading.Thread]::CurrentThread.CurrentCulture = $culture
                }
                Try {
                    Set-Culture en-US
                    $FoundEvents = Get-WinEvent -ComputerName $servername -FilterHashtable @{Logname='Security';Id=4624;Data=$UID} -ErrorAction Stop -MaxEvents 1
                }
                Catch {
                    $SearchError = $_
                }
                If ($FoundEvents) {
                    $SearchError = '-'
                    $uktime = Get-Date -Date $FoundEvents.TimeCreated -Format "dd/MM/yyyy HH:mm:ss" # Convert date back to UK format
                    Try {
                        $ResHostName = (Resolve-Host $FoundEvents.Properties.Value[18] -ErrorAction Stop).HostName
                    }
                    Catch {
                        $ResHostName = 'Not known'
                    }
                    [PSCustomObject]@{
                        UID = $FoundEvents.Properties.Value[5]
                        IPAddress = $FoundEvents.Properties.Value[18]
                        HostName = $ResHostName
                        LogonTime = $uktime
                        Status = $SearchError
                    }
                }
            } -ErrorAction Stop
        }
        Catch {
            $ProgressBox.AppendText("`r`nError starting job" + $_)
        }
    }
    # Pick up jobs
    $TimeOutCounter = 0
    $ProgressBox.AppendText("`r`nWaiting for running jobs to complete, please wait...")
    Do { 
        Get-Job -State Completed | ForEach-Object { 
            $JobName = $_.Name
            $ProgressBox.AppendText("`r`nJob complete for $JobName, retrieving data`r`n")
            $JobResult = Receive-Job -Name $JobName
            $SessionList += $JobResult     
            Remove-Job -Name ($_.Name)
        }
        Get-Job -State Failed | ForEach-Object {
            $ProgressBox.AppendText("`r`nJob failed for $($_.Name)`r`n")
            $JobResult = Receive-Job -Name ($_.Name) 
            $SessionList += $JobResult     
            Remove-Job -Name ($_.Name)
        }
        If(Get-Job -State Running) {
            $ProgressBox.AppendText('.')
            Start-Sleep $SleepTime 
            $TimeOutCounter += $SleepTime
            If($TimeOutCounter -ge $TimeOut) { 
                $ProgressBox.AppendText("`r`nTime out... $TimeOut. Cancelling unfinished jobs...")
                Get-Job | ForEach-Object {
                    $ProgressBox.AppendText("`r`nCancelling: " + $_.Name + " please wait...")
                    Remove-Job -Name $_.name -Force
                }
            } 
        }
    } While (Get-Job)
    $ProgressBox.AppendText("`r`nEvent logs scanning complete")
    $ProgressBox.AppendText("`r`nFiltering data and checking logon status...")
    #
	# Sort session list and select only most recent logon event for each hostname/IP
    $SessionList | Group-Object 'Hostname' | ForEach-Object {
        $_.Group | Sort-Object LogonTime | Select-Object UID,IPAddress,HostName,LogonTime -Last 1
    } | ForEach-Object {
		# Get current status of the session
		$CurUID = $_.UID
		Try {
            $HostLoginStatus = Get-LoggedOnUser -ComputerName $_.IPAddress -ErrorAction Stop | Where-Object { $_.UserName -eq $CurUID	}
        }
        Catch {
            $ProgressBox.AppendText("$_")
        }
        If (-not $HostLoginStatus) {
            $Status = 'No login'
        }
        ElseIf($HostLoginStatus.State) {
			$Status = $HostLoginStatus.State
		}
		Else {
			$Status = $HostLoginStatus.Error
		}
        $Entry = New-Object System.Windows.Forms.ListViewItem($_.UID)
        $Entry.SubItems.Add($_.IPAddress) | Out-Null
        $Entry.SubItems.Add($_.HostName) | Out-Null
		$Entry.SubItems.Add($_.LogonTime) | Out-Null
		$Entry.SubItems.Add($Status) | Out-Null
        $LogonList.Items.Add($Entry) | Out-Null
    }
    $ScanButton.Enabled = $true
    $ScanTimeout.Enabled = $true
	$SearchButton.Enabled = $true
    $ProgressBox.AppendText("`r`nScan complete")
})
#
$form.Add_Shown({
    #
    $CurrentUser = Get-ADUser $env:USERNAME
    $CurUserLbl.Text = ("Current credentials: " + $CurrentUser.givenname + " " + $CurrentUser.surname)
    $DomainControllers = Get-ADDomainController -Filter * | Sort-Object HostName
    $DCList.BeginUpdate()
    $DomainControllers | ForEach-Object {
        $Entry = New-Object System.Windows.Forms.ListViewItem($_.Name)
        $Entry.SubItems.Add($_.Site) | Out-Null
        $Entry.SubItems.Add($_.OperatingSystem) | Out-Null
    	If ($_.Name -notin $DCExclude) {
	    	$Entry.Checked = $true
	    }
        $DCList.Items.Add($Entry) | Out-Null
    }
    $DCList.EndUpdate()
})
#
#  Show form
#
$form.Activate()
$form.ShowDialog() | Out-Null
$form.Dispose()
#

