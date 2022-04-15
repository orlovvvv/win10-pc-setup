
#Elevate powershell instance to enable changes to system
Write-Host "Elevate powershell instance"
    if (!
        #current role
        (New-Object Security.Principal.WindowsPrincipal(
            [Security.Principal.WindowsIdentity]::GetCurrent()
        #is admin?
        )).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator
        )
    ) {
        #elevate script and exit current non-elevated runtime
        Start-Process `
            -FilePath 'powershell' `
            -ArgumentList (
                #flatten to single array
                '-File', $MyInvocation.MyCommand.Source, $args `
                | %{ $_ }
            ) `
            -Verb RunAs
        exit
    }

#--------------------------------------------------------------------------------------------------------------------------------------

# Check if winget is installed
Write-Host "Checking winget"
    if (Test-Path ~\AppData\Local\Microsoft\WindowsApps\winget.exe){
        'Winget Already Installed'
    }  
    else{
        # Installing winget from the Microsoft Store
        Write-Host "Winget not found, installing it now."
        $ResultText.text = "`r`n" +"`r`n" + "Installing Winget... Please Wait"
        Start-Process "ms-appinstaller:?source=https://aka.ms/getwinget"
        $nid = (Get-Process AppInstaller).Id
        Wait-Process -Id $nid
        Write-Host Winget Installed
    }

#--------------------------------------------------------------------------------------------------------------------------------------

$Bloatware = @(

    "Microsoft.3DBuilder"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.AppConnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.MinecraftUWP"
    "Microsoft.GamingServices"
    "Microsoft.WindowsReadingList"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.News"
    "Microsoft.Office.Lens"
    "Microsoft.Office.Sway"
    "Microsoft.Office.OneNote"
    "Microsoft.OneConnect"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.Whiteboard"
    "Microsoft.WindowsAlarms"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.XboxApp"
    "Microsoft.ConnectivityStore"
    "Microsoft.CommsPhone"
    "Microsoft.ScreenSketch"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.MixedReality.Portal"
    "Microsoft.XboxIdentityProvider"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.YourPhone"
    "Microsoft.Getstarted"
    "*Office*"
    "*OneDrive*"
    "*EclipseManager*"
    "*ActiproSoftwareLLC*"
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
    "*Duolingo-LearnLanguagesforFree*"
    "*PandoraMediaInc*"
    "*CandyCrush*"
    "*BubbleWitch3Saga*"
    "*Wunderlist*"
    "*Flipboard*"
    "*Twitter*"
    "*Facebook*"
    "*Royal Revolt*"
    "*Sway*"
    "*Speed Test*"
    "*Dolby*"
    "*Viber*"
    "*ACGMediaPlayer*"
    "*Netflix*"
    "*OneCalendar*"
    "*LinkedInforWindows*"
    "*HiddenCityMysteryofShadows*"
    "*Hulu*"
    "*HiddenCity*"
    "*AdobePhotoshopExpress*"
    "*HotspotShieldFreeVPN*"
    "*Microsoft.Advertising.Xaml*"
)
# Go through loop of bloatware to remove
foreach ($Bloat in $Bloatware) {
        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
        Write-Host "Trying to remove $Bloat."
    }

    Write-Host "Finished Removing Bloatware Apps"

#--------------------------------------------------------------------------------------------------------------------------------------

# Software installation for PCs in SPZOZ Parczew
Write-Host "Installing chocolatey"
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
Update-SessionEnvironment

Write-Host "Installation of software for computers in SPZOZ w Parczewie (No MSOffice, No NAPS2)"
choco feature enable -n allowGlobalConfirmation
#   Adobe Reader
choco install adobereader
#   Bandizip
choco install bandizip
#   MPV Player
choco install mpv
#   Thunderbird
choco install thunderbird
#   Firefox ESR
choco install firefoxesr
#   Firefox ESR
choco install firefoxesr
#   TightVNC
choco install tightvnc
#   LibreOffice Stable
choco install libreoffice-still
#   NAPS2
#choco install naps2

choco feature disable -n allowGlobalConfirmation

Write-Host "Installation complete"
 
#--------------------------------------------------------------------------------------------------------------------------------------
 
#   Add firewall rules
Write-Host "Applying ICMP, WOL and RDP rules to firewall"

netsh advfirewall firewall add rule name="ALL ICMP v4 ping echo request" protocol=icmpv4:8,any dir=in action=allow

netsh advfirewall firewall add rule name="WAKE ON LAN" protocol=UDP localport=9 dir=in action=allow

netsh advfirewall firewall set rule group="Pulpit zdalny" new enable=no

Write-Host "Firewall rules applied"

#--------------------------------------------------------------------------------------------------------------------------------------
 
#   Disable unwatned Windows services:
$services = @(
    "diagnosticshub.standardcollector.service"     #Microsoft (R) Diagnostics Hub Standard Collector Service
    "DiagTrack"                                    #Diagnostics Tracking Service
    "dmwappushservice"                             #WAP Push Message Routing Service (see known issues)
    "lfsvc"                                        #Geolocation Service
    "MapsBroker"                                   #Downloaded Maps Manager
    "NetTcpPortSharing"                            #Net.Tcp Port Sharing Service
    "RemoteAccess"                                 #Routing and Remote Access
    "RemoteRegistry"                               #Remote Registry
    "SharedAccess"                                 #Internet Connection Sharing (ICS)
    "TrkWks"                                       #Distributed Link Tracking Client
    "WbioSrvc"                                     #Windows Biometric Service (required for Fingerprint reader / facial detection)
    "WMPNetworkSvc"                                #Windows Media Player Network Sharing Service
    "WSearch"                                      #Windows Search
    "XblAuthManager"                               #Xbox Live Auth Manager
    "XblGameSave"                                  #Xbox Live Game Save Service
    "XboxNetApiSvc"                                #Xbox Live Networking Service
    "XboxGipSvc"                                   #Disables Xbox Accessory Management Service
    "ndu"                                          #Windows Network Data Usage Monitor
    "WerSvc"                                       #disables windows error reporting
    "Spooler"                                      #Disables your printer
    "Fax"                                          #Disables fax
    "fhsvc"                                        #Disables fax histroy
    "gupdate"                                      #Disables google update
    "gupdatem"                                     #Disable another google update
    "stisvc"                                       #Disables Windows Image Acquisition (WIA)
    "AJRouter"                                     #Disables (needed for AllJoyn Router Service)
    "MSDTC"                                        #Disables Distributed Transaction Coordinator
    "WpcMonSvc"                                    #Disables Parental Controls
    "PhoneSvc"                                     #Disables Phone Service(Manages the telephony state on the device)
    "PrintNotify"                                  #Disables Windows printer notifications and extentions
    "PcaSvc"                                       #Disables Program Compatibility Assistant Service
    "WPDBusEnum"                                   #Disables Portable Device Enumerator Service
    "seclogon"                                     #Disables  Secondary Logon(disables other credentials only password will work)
    "SysMain"                                      #Disables sysmain
    "lmhosts"                                      #Disables TCP/IP NetBIOS Helper
    "wisvc"                                        #Disables Windows Insider program(Windows Insider will not work)
    "FontCache"                                    #Disables Windows font cache
    "RetailDemo"                                   #Disables RetailDemo whic is often used when showing your device
    "ALG"                                          #Disables Application Layer Gateway Service(Provides support for 3rd party protocol plug-ins for Internet Connection Sharing)
    "SCardSvr"                                     #Disables Windows smart card
    "BthAvctpSvc"                                  #Disables AVCTP service (if you use  Bluetooth Audio Device or Wireless Headphones. then don't disable this)
    "FrameServer"                                  #Disables Windows Camera Frame Server(this allows multiple clients to access video frames from camera devices.)
    "Browser"                                      #Disables computer browser
    "BthAvctpSvc"                                  #AVCTP service (This is Audio Video Control Transport Protocol service.)
    "BDESVC"                                       #Disables bitlocker
    "iphlpsvc"                                     #Disables ipv6 but most websites don't use ipv6 they use ipv4     
    "edgeupdate"                                   #Disables one of edge update service  
    "MicrosoftEdgeElevationService"                #Disables one of edge  service 
    "edgeupdatem"                                  #Disables another one of update service (disables edgeupdatem)                          
    "SEMgrSvc"                                     #Disables Payments and NFC/SE Manager (Manages payments and Near Field Communication (NFC) based secure elements)
    "PerfHost"                                     #Disables  remote users and 64-bit processes to query performance .
    "BcastDVRUserService_48486de"                  #Disables GameDVR and Broadcast   is used for Game Recordings and Live Broadcasts
    "CaptureService_48486de"                       #Disables ptional screen capture functionality for applications that call the Windows.Graphics.Capture API.  
    "cbdhsvc_48486de"                              #Disables   cbdhsvc_48486de (clipboard service it disables)
    "BluetoothUserService_48486de"                 #Disables BluetoothUserService_48486de (The Bluetooth user service supports proper functionality of Bluetooth features relevant to each user session.)
    "WpnService"                                   #Disables WpnService (Push Notifications may not work )
    #"StorSvc"                                     #Disables StorSvc (usb external hard drive will not be reconised by windows)
    "RtkBtManServ"                                 #Disables Realtek Bluetooth Device Manager Service
    "QWAVE"                                        #Disables Quality Windows Audio Video Experience (audio and video might sound worse)
     #Hp services just in case
    "HPAppHelperCap"
    "HPDiagsCap"
    "HPNetworkCap"
    "HPSysInfoCap"
    "HpTouchpointAnalyticsService"
    #hyper-v services
    "HvHost"                          
    "vmickvpexchange"
    "vmicguestinterface"
    "vmicshutdown"
    "vmicheartbeat"
    "vmicvmsession"
    "vmicrdv"
    "vmictimesync" 
    # Services which cannot be disabled
    #"WdNisSvc"
)

Write-Host " Disabling unwatned Windows services"
foreach ($service in $services) {
    # -ErrorAction SilentlyContinue is so it doesn't write an error to stdout if a service doesn't exist

    Write-Host "Setting $service StartupType to disabled"
    Get-Service -Name $service -ErrorAction SilentlyContinue | Set-Service -StartupType Disabled

    $running = Get-Service -Name $service -ErrorAction SilentlyContinue | Where-Object {$_.Status -eq 'Running'}
    if ($running) { 
        Write-Host "Stopping $service"
        Stop-Service -Name $service
    }
}
 
#--------------------------------------------------------------------------------------------------------------------------------------

#Diable Action Center 
Write-Host "Disabling Action Center"
    If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0
    Write-Host "Disabled Action Center"
     
#--------------------------------------------------------------------------------------------------------------------------------------

#Improve Windows Update policies
Write-Host "Disabling driver offering through Windows Update"
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value 1
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontPromptForWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DontSearchWindowsUpdate" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DriverSearching" -Name "DriverUpdateWizardWuSearchEnabled" -Type DWord -Value 0
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "ExcludeWUDriversInQualityUpdate" -Type DWord -Value 1
    Write-Host "Disabling Windows Update automatic restart..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value 1
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "AUPowerManagement" -Type DWord -Value 0
    Write-Host "Policies updated"
     
#--------------------------------------------------------------------------------------------------------------------------------------

#Show all tray icons
Write-Host "Showing tray icons"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0
	Write-Host "Done - Now showing all tray icons"
     
#--------------------------------------------------------------------------------------------------------------------------------------

# Disable hibernation
Write-Host "Disable hibernation"
    powercfg /h off

Pause

