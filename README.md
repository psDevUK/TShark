# TShark

PowerShell Crescendo module for TShark command line of Wireshark.

![](https://img.shields.io/powershellgallery/dt/tshark?style=for-the-badge)

# Installation 

This module does not include the commands that it wraps. You can install them with scoop or Chocolatey. Or if you don't want you copy and paste, I did include a function 

```powershell
Install-TShark
```
Which will check if scoop present if not will install scoop and wireshark, if scoop is installed it will just install wireshark, if you don't already have it installed

# Manual Install from scoop

```powershell
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('https://get.scoop.sh')
scoop bucket add extras
scoop install wireshark
```
# Manual Install from Chocolatey

```powershell
choco install wireshark
```
# Install this module from PSGallery, or take a fork

To install this module: 

```powershell
Install-Module TShark
```

# Why Do this Module?
 
Inspired by the Sysinternals module Adam Driscoll had released I used the methods documented to create another command line tool. I think this TShark and Wireshark are both amazing tools, and I have had to look through a fair few network captures recently. So as with all things in life, why not try to automate the process, or have a more familiar way to do something.
I was using the GUI Wireshark to perform my captures, as I initially found the parameter list too over-whelming to absorb for TShark. So I have taken the time to re-invent TShark to be called using a function with dynamic parameter lists that hopefully make a bit more sense, I tried to use the verb-noun approach where I could. This was a fun project to do and hopefully will be of great use to add to your own tool-kit you have to do particular jobs.

# Help

```powershell
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
```
