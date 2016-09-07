$minimumCertAgeDays = 60
$timeoutMilliseconds = 10000
$datafolder = C:\DMD\CertChk\
#$urls = @(
# "https://myub.buffalo.edu",
# "https://mdm.cit.buffalo.edu/login"
#)

$urls = @(Get-Content C:\dmd\CertChk\servers.txt)
$servercerts = @()

#disabling the cert validation check. This is what makes this whole thing work with invalid certs...
[Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
foreach ($url in $urls)
{
	Write-Host Checking $url -f Green
	$req = [Net.HttpWebRequest]::Create($url)
	$req.Timeout = $timeoutMilliseconds
	try {$req.GetResponse() |Out-Null} catch {Write-Host Exception while checking URL $url`: $_ -f Red}
	[datetime]$expiration = $req.ServicePoint.Certificate.GetExpirationDateString()
	[int]$certExpiresIn = ($expiration - $(get-date)).Days
	$certName = $req.ServicePoint.Certificate.GetName()
	$certPublicKeyString = $req.ServicePoint.Certificate.GetPublicKeyString()
	$certSerialNumber = $req.ServicePoint.Certificate.GetSerialNumberString()
	$certThumbprint = $req.ServicePoint.Certificate.GetCertHashString()
	$certEffectiveDate = $req.ServicePoint.Certificate.GetEffectiveDateString()
	$certIssuer = $req.ServicePoint.Certificate.GetIssuerName()
		
	$details = @{
			Server			= $url
			ExpireDays		= $certExpiresIn
			Expiration		= $expiration
			CertName		= $certName
			CertIssuer		= $certIssuer
	}
	$servercerts += New-Object PSObject -Property $details
	
	if ($certExpiresIn -gt $minimumCertAgeDays)
		{Write-Host Cert for site $url expires in $certExpiresIn days [on $expiration] -f Green}
	else
		{Write-Host Cert for site $url expires in $certExpiresIn days [on $expiration] Threshold is $minimumCertAgeDays days. Check details:`n`nCert name: $certName`nCert public key: $certPublicKeyString`nCert serial number: $certSerialNumber`nCert thumbprint: $certThumbprint`nCert effective date: $certEffectiveDate`nCert issuer: $certIssuer -f Red}
	rv req
	rv expiration
	rv certExpiresIn
}
$servercerts | Export-CSV -NoTypeInformation -Path C:\DMD\CertChk\servercerts.csv