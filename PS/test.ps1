# Parameter help description
param($ticketNumber)
$apiKey = "NZEDaffyf4Ggk4WuH5cuDRDMfthxOAg8XMeSNGPT"
$baseurl = "https://afishelpdesk/helpdesk/WebObjects/Helpdesk.woa/ra/Tickets/"


#Get json detail of the ticket
##Construct URL using the ticketnumber

$url = $baseurl+$ticketNumber+"?"+$apiKey
#Write-Host $url

##Get Ticket detail
$ticket = Invoke-RestMethod -Uri $url
$detail = $ticket.detail
$file = "ticketdetail.txt"
Set-Content -Path $file -Value $detail

Write-Host $detail

##Read File

##Get Display Name
###Get Display Name line number
$dnlinenum = (Select-String -Path $file -Pattern "Display Name" |Select-Object -ExpandProperty LineNumber)
###Get the contect of line after "Display Name"
$dnline = (Get-Content $file)[$dnlinenum]
###Remove "<br/> " from the line
$dn = $dnline.Remove(0,6)
###Split name into first and lastname
$last, $firstname = $dn.Split(" ")
###Remove comma at the end of the lastname
$lastname = $last -replace ","
#Write-Host "Last Name"
Write-Host $lastname
Write-Host $firstname
##Get Username
###Get UserName line number
$unlinenum = (Select-String -Path $file -Pattern "Username" |Select-Object -ExpandProperty LineNumber)
###Get the content of the line after "Username"
$unline = (Get-Content $file)[$unlinenum]
#Write-Host $unline
###Remove "<br/> " from the line
$username = $unline.Remove(0,6)
Write-Host $username



##Get Job Title
###Get Job Title line number
$jtlinenum = (Select-String -Path $file -Pattern "Job Title" |Select-Object -ExpandProperty LineNumber)
###Get the content of the line after "Job Title"
$jtline = (Get-Content $file)[$jtlinenum]
###Remove "<br/> " from the line
$jobtitle = $jtline.Remove(0,6)
Write-Host $jobtitle

