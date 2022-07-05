# Module created by Microsoft.PowerShell.Crescendo
class PowerShellCustomFunctionAttribute : System.Attribute { 
    [bool]$RequiresElevation
    [string]$Source
    PowerShellCustomFunctionAttribute() { $this.RequiresElevation = $false; $this.Source = "Microsoft.PowerShell.Crescendo" }
    PowerShellCustomFunctionAttribute([bool]$rElevation) {
        $this.RequiresElevation = $rElevation
        $this.Source = "Microsoft.PowerShell.Crescendo"
    }
}

function Start-TShark
{
[PowerShellCustomFunctionAttribute(RequiresElevation=$False)]
[CmdletBinding()]

param(
[Parameter()]
[String]$SetInterface,
[Parameter()]
[String]$SetCaptureFilter,
[Parameter()]
[Switch]$SetDataLinkType,
[Parameter()]
[Switch]$GetInterfaces,
[Parameter()]
[Switch]$GetDataLinkTypes,
[Parameter()]
[String]$Path,
[Parameter()]
[ValidateSet("pcap","pcapng","5views","btsnoop","commview-ncf","commview-ncfx","dct2000","erf","eyesdn","k12text","lanalyzer","logcat","logcat-brief","logcat-long","logcat-process","logcat-tag","logcat-thread","logcat-threadtime","logcat-time","modpcap","netmon1","netmon2","nettl","ngsniffer","ngwsniffer_1_1","ngwsniffer_2_0","nokiapcap","nsecpcap","nstrace10","nstrace20","nstrace30","nstrace35","observer","rf5","rh6_1pcap","snoop","suse6_3pcap","visual")]
[String]$SetFileType,
[Parameter()]
[String]$LogPath,
[Parameter()]
[ValidateScript(
    {if ($_ -match "filesize:[0-9]+$")
     {
       $true  
     }
     else
     {
         throw 'use filesize: followed by number which represents KiloBytes Example:- filesize:1024 this will output 1mb capture files.'
     }
  })]
  [ArgumentCompleter(
    {
      param($cmd, $param, $wordToComplete)
      # This is the duplicated part of the code in the [ValidateScipt] attribute.
      [array] $validValues = [regex]"filesize:[0-9]+$"
      $validValues -like "$wordToComplete*"
    }
  )]
[String]$SetFileCaptureSizeKB,
[Parameter()]
[ValidateScript(
    {if ($_ -match "duration:[0-9]+$")
     {
       $true  
     }
     else
     {
         throw 'use duration: followed by number which represents seconds in time Example:- duration:60 this will output a capture files 60 seconds apart.'
     }
  })]
  [ArgumentCompleter(
    {
      param($cmd, $param, $wordToComplete)
      # This is the duplicated part of the code in the [ValidateScipt] attribute.
      [array] $validValues = [regex]"duration:[0-9]+$"
      $validValues -like "$wordToComplete*"
    }
  )]
[String]$SetFileCaptureDuration,
[Parameter()]
[ValidateScript(
    {if ($_ -match "files:[0-9]+$")
     {
       $true  
     }
     else
     {
         throw 'use files: followed by number which represents the number of 5 in total to capture Example:- files:10 this will output 10 capture files and then replace.'
     }
  })]
  [ArgumentCompleter(
    {
      param($cmd, $param, $wordToComplete)
      # This is the duplicated part of the code in the [ValidateScipt] attribute.
      [array] $validValues = [regex]"files:[0-9]+$"
      $validValues -like "$wordToComplete*"
    }
  )]
[String]$SetNumberCaptureFiles,
[Parameter()]
[Switch]$GetVersion,
[Parameter()]
[String]$OpenFile,
[Parameter()]
[ValidateSet("expert","afp,srt","ancp,tree","ansi_a,bsmap","ansi_a,dtap","ansi_map","asap,stat","bacapp_instanceid,tree","bacapp_ip,tree","bacapp_objectid,tree","bacapp_service,tree","calcappprotocol,stat","camel,counter","camel,srt","collectd,tree","componentstatusprotocol,stat","conv,bluetooth","conv,dccp","conv,eth","conv,fc","conv,fddi","conv,ip","conv,ipv6","conv,ipx","conv,jxta","conv,mptcp","conv,ncp","conv,rsvp","conv,sctp","conv,sll","conv,tcp","conv,tr","conv,udp","conv,usb","conv,wlan","conv,wpan","conv,zbee_nwk","credentials","dcerpc,srt","dests,tree","dhcp,stat","diameter,avp","diameter,srt","dns,tree","endpoints,bluetooth","endpoints,dccp","endpoints,eth","endpoints,fc","endpoints,fddi","endpoints,ip","endpoints,ipv6","endpoints,ipx","endpoints,jxta","endpoints,mptcp","endpoints,ncp","endpoints,rsvp","endpoints,sctp","endpoints,sll","endpoints,tcp","endpoints,tr","endpoints,udp","endpoints,usb","endpoints,wlan","endpoints,wpan","endpoints,zbee_nwk","enrp,stat","expert","f1ap,tree","f5_tmm_dist,tree","f5_virt_dist,tree","fc,srt","flow,any","flow,icmp","flow,icmpv6","flow,lbm_uim","flow,tcp","follow,dccp","follow,http","follow,http2","follow,quic","follow,sip","follow,tcp","follow,tls","follow,udp","fractalgeneratorprotocol,stat","gsm_a","gsm_a,bssmap","gsm_a,dtap_cc","gsm_a,dtap_gmm","gsm_a,dtap_mm","gsm_a,dtap_rr","gsm_a,dtap_sacch","gsm_a,dtap_sm","gsm_a,dtap_sms","gsm_a,dtap_ss","gsm_a,dtap_tp","gsm_map,operation","gtp,srt","h225,counter","h225_ras,rtd","hart_ip,tree","hosts","hpfeeds,tree","http,stat","http,tree","http2,tree","http_req,tree","http_seq,tree","http_srv,tree","icmp,srt","icmpv6,srt","io,phs","io,stat","ip_hosts,tree","ip_srcdst,tree","ipv6_dests,tree","ipv6_hosts,tree","ipv6_ptype,tree","ipv6_srcdst,tree","isup_msg,tree","lbmr_queue_ads_queue,tree","lbmr_queue_ads_source,tree","lbmr_queue_queries_queue,tree","lbmr_queue_queries_receiver,tree","lbmr_topic_ads_source,tree","lbmr_topic_ads_topic,tree","lbmr_topic_ads_transport,tree","lbmr_topic_queries_pattern,tree","lbmr_topic_queries_pattern_receiver,tree","lbmr_topic_queries_receiver,tree","lbmr_topic_queries_topic,tree","ldap,srt","mac-lte,stat","megaco,rtd","mgcp,rtd","mtp3,msus","ncp,srt","ngap,tree","npm,stat","osmux,tree","pingpongprotocol,stat","plen,tree","proto,colinfo","ptype,tree","radius,rtd","rlc-lte,stat","rpc,programs","rpc,srt","rtp,streams","rtsp,stat","rtsp,tree","sametime,tree","scsi,srt","sctp,stat","sip,stat","smb,sids","smb,srt","smb2,srt","smpp_commands,tree","snmp,srt","ssprotocol,stat","sv","ucp_messages,tree","wsp,stat")]
[String]$GetStatistics
    )

BEGIN {
    $__PARAMETERMAP = @{
         SetInterface = @{
               OriginalName = '-i'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
         SetCaptureFilter = @{
               OriginalName = '-f'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
         SetDataLinkType = @{
               OriginalName = '-y'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'Switch'
               ApplyToExecutable = $False
               NoGap = $False
               }
         GetInterfaces = @{
               OriginalName = '-D'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'Switch'
               ApplyToExecutable = $False
               NoGap = $False
               }
         GetDataLinkTypes = @{
               OriginalName = '-L'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'Switch'
               ApplyToExecutable = $False
               NoGap = $False
               }
         Path = @{
               OriginalName = '-w'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
         SetFileType = @{
               OriginalName = '-F'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
         LogPath = @{
               OriginalName = '--log-file'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
         SetFileCaptureSizeKB = @{
               OriginalName = '-b'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
         SetFileCaptureDuration = @{
               OriginalName = '-b'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
         SetNumberCaptureFiles = @{
               OriginalName = '-b'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
         GetVersion = @{
               OriginalName = '-v'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'Switch'
               ApplyToExecutable = $False
               NoGap = $False
               }
        OpenFile = @{
               OriginalName = '-r'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
        GetStatistics = @{
               OriginalName = '-z'
               OriginalPosition = '0'
               Position = '2147483647'
               ParameterType = 'String'
               ApplyToExecutable = $False
               NoGap = $False
               }
    }

    $__outputHandlers = @{ Default = @{ StreamOutput = $true; Handler = { $input } } }
}

PROCESS {
    $__boundParameters = $PSBoundParameters
    $__defaultValueParameters = $PSCmdlet.MyInvocation.MyCommand.Parameters.Values.Where({$_.Attributes.Where({$_.TypeId.Name -eq "PSDefaultValueAttribute"})}).Name
    $__defaultValueParameters.Where({ !$__boundParameters["$_"] }).ForEach({$__boundParameters["$_"] = get-variable -value $_})
    $__commandArgs = @()
    $MyInvocation.MyCommand.Parameters.Values.Where({$_.SwitchParameter -and $_.Name -notmatch "Debug|Whatif|Confirm|Verbose" -and ! $__boundParameters[$_.Name]}).ForEach({$__boundParameters[$_.Name] = [switch]::new($false)})
    if ($__boundParameters["Debug"]){wait-debugger}
    foreach ($paramName in $__boundParameters.Keys|
            Where-Object {!$__PARAMETERMAP[$_].ApplyToExecutable}|
            Sort-Object {$__PARAMETERMAP[$_].OriginalPosition}) {
        $value = $__boundParameters[$paramName]
        $param = $__PARAMETERMAP[$paramName]
        if ($param) {
            if ($value -is [switch]) {
                 if ($value.IsPresent) {
                     if ($param.OriginalName) { $__commandArgs += $param.OriginalName }
                 }
                 elseif ($param.DefaultMissingValue) { $__commandArgs += $param.DefaultMissingValue }
            }
            elseif ( $param.NoGap ) {
                $pFmt = "{0}{1}"
                if($value -match "\s") { $pFmt = "{0}""{1}""" }
                $__commandArgs += $pFmt -f $param.OriginalName, $value
            }
            else {
                if($param.OriginalName) { $__commandArgs += $param.OriginalName }
                $__commandArgs += $value | Foreach-Object {$_}
            }
        }
    }
    $__commandArgs = $__commandArgs | Where-Object {$_ -ne $null}
    if ($__boundParameters["Debug"]){wait-debugger}
    if ( $__boundParameters["Verbose"]) {
         Write-Verbose -Verbose -Message tshark.exe
         $__commandArgs | Write-Verbose -Verbose
    }
    $__handlerInfo = $__outputHandlers[$PSCmdlet.ParameterSetName]
    if (! $__handlerInfo ) {
        $__handlerInfo = $__outputHandlers["Default"] # Guaranteed to be present
    }
    $__handler = $__handlerInfo.Handler
    if ( $PSCmdlet.ShouldProcess("tshark.exe $__commandArgs")) {
    # check for the application and throw if it cannot be found
        if ( -not (Get-Command -ErrorAction Ignore "tshark.exe")) {
          throw "Cannot find executable 'tshark.exe'"
        }
        if ( $__handlerInfo.StreamOutput ) {
            & "tshark.exe" $__commandArgs | & $__handler
        }
        else {
            $result = & "tshark.exe" $__commandArgs
            & $__handler $result
        }
    }
  } # end PROCESS

<#
.SYNOPSIS
This is allowing you to run TShark.exe in powershell using powershell
.DESCRIPTION 
Inspired by Adam Driscoll and the Sysinternals module I wanted to do something similar 
so bringing tshark to powershell. Although this module does not at the moment include
every single parameter tshark does, I still think it was worth bringing this to powershell
to act as another tool for the sysadmins tool-kit you have. I like hanging out in my shell
all day so this now allows me to easily use tshark from Powershell

.PARAMETER SetInterface
This is the same as the -i parameter in tshark but with a more helpful paramter name I think. So this
will set the name of the network interface to use for live packet capture.  Please note to get a list
of YOUR valid network interfaces use the -GetInterface paramter first.

.PARAMETER SetCaptureFilter
Set the capture filter expression using wireshark syntax, to only filter on dns just simply type dns after this
parameter name. Please do not use this if you are un-sure of the syntax, you can always filter the capture file in the
wireshark GUI after the capture is complete.

.PARAMETER SetDataLinkType
Set the data link type to use while capturing packets. The values reported by -GetDataLinkTypes are the values that can be used
as the value for this parameter

.PARAMETER GetInterfaces
Print a list of the interfaces on which TShark can capture, and exit. For each network interface, a number and an interface name,
possibly followed by a text description of the interface, is printed. The interface name or the number can be supplied to the -SetInterface option to specify an interface on which to capture.

.PARAMETER GetDataLinkTypes
List the data link types supported by the interface and exit. The reported link types can be used with the -SetDataLinkTypes
parameter

.PARAMETER Path
Type the full file output path you want the file to go to including the file name and file extension. For example:-
-Path C:\Users\MyAccount\MyCapture.pcapng

.PARAMETER SetFileType
This allows you to see all the possible file extension output types. So you can select a different output to the default
pcapng format should you so wish to. Please remember to also specify this in the -Path value the parameter file-type
extension you selected  

.PARAMETER LogPath
This will allow you to specify a .txt or .log file to output messages to that appear on the screen during the capture

.PARAMETER SetFileCaptureSizeKB
This is using the capture ring buffer option from tshark -b and using this to set the file size for the capture you wish to
perform. After using this parameter name press TAB to auto-complete the parameter validation pattern

.PARAMETER SetFileCaptureDuration
This is using the capture ring buffer option from tshark -b this will set the amount of time in seconds that the capture is taken for to a file before going to the next file.
After using this parameter name press TAB to auto-complete the parameter validation pattern

.PARAMETER SetNumberCaptureFiles
This is using the capture ring buffer option from tshark -b allowing you to set the number of rotating capture files you wish to
capture. You would use this parameter in with either the -SetFileCaptureSizeKB or -SetFileCaptureDuration to allow you to
fix the amount of files to store in the output directory. This will allow you to keep a trace running for days without flooding 
the hard drive full of data. After using this parameter name press TAB to auto-complete the parameter validation pattern

.PARAMETER GetVersion
This will display the current version of tshark you are using in the background to perform the task at hand.

.PARAMETER OpenFile
Allows you to display a capture file within the Powershell window you have open, should you wish to do some quick analysis
on the capture

.PARAMETER GetStatistics
This allows you to choose from a large choice of statistics to display after it has opened the capture file. This is very
useful to gain certain insights or to just get the expert statistics

.EXAMPLE
   Start-TShark -Path C:\Zelda.pcapng -SetFileCaptureSizeKB filesize:10240 -SetNumberCaptureFiles files:10
This will output a rotating set of 10 files which will be 10MB in size. Pressing CTRL+C to exit the capture after the
desired issue has been captured

.EXAMPLE
  Start-TShark -SetInterface "Wi-Fi" -Path C:\DnsOutput.pcapng -LogPath C:\DnsOutput.txt
This will being a capture on the Wi-Fi network interface, outputting to a .pcapng file and also record the output
from messages on the Powershell screen to the log file specified in the -LogPath this file capture will continue
to capture information until CTRL+C is pressed to stop the capture

.EXAMPLE
 Start-TShark -OpenFile C:\SlowNetwork.pcapng -GetStatistics expert
 Will open the capture file specified in the -OpenFile parameter, this will also then provide you with the expert analysis
 information by specifying that value from the pre-defined list of choices on the -GetStatistics parameter

.FUNCTIONALITY
To use when you have a weird network issue you have been told to fix, allowing you to collect packet information to analyze
in Wireshark 
#>
}


