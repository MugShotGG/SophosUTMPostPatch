Param(
    [Parameter(Mandatory=$true)]
    [bool]
    $IsNewCert,

    [Parameter(Mandatory=$true)]
    [String]
    $Domain,

    [Parameter(Mandatory=$true)]
    [String]
    $CertPath,

    [Parameter(Mandatory=$true)]
    [String]
    $KeyPath
)

Function 509Body {

#Form Body
$x509Json = @"
{
            "comment": "upload",
            "enddate": "$notAfter",
            "fingerprint": "$fingerprint",
            "issuer": "$Issuer",
            "issuer_hash": "$isshash",
            "name": "$name",
            "public_key_algorithm": "$keyalg",
            "serial": "$certserial",
            "startdate": "$NotBefore",
            "subject": "$subject",
            "subject_alt_names": ["$SAN"],
            "subject_hash": "$subhash",
            "vpn_id": "$VNPId",
            "vpn_id_type": "fqdn"
}
"@


return $x509Json
}

Function CertBody {


$CA = "REF_CaVerLetsEncryCa"

#pull info from cert

$CertContent = (Get-Content $CertPath) | Out-String
$KeyContent = (Get-Content $KeyPath) | Out-String
$CertAsText = openssl x509 -in $CertPath -noout -text | Out-String
$509Format = "$CertAsText" + "$CertContent"


#cert body 
$body =  [ordered]@{
            name= "$VNPId"
            ca= "$CA"
            certificate= "$509Format"
            comment= "AutomatedTM"
            encrypted= $false
            key= "$KeyContent"
            meta= "$509Ref"
     } 

$json = ConvertTo-Json $body

return $json

}

# $IsNewCert = $true 
# $Domain = '*.demo2.com'
# $CertPath =  $Cert.CertFile
# $KeyPath = $Cert.KeyFile
Write-verbose $IsNewCert 
Write-verbose $Domain 
Write-verbose $CertPath 
Write-verbose $KeyPath 


#Auth/Creds

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$BaseURL = "https://XXXX:4444/api/"
$token = ''
$tokenBase64 = [Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes("token:" + $token))
$headers = @{}
$headers.add("Authorization",'Basic ' + $tokenBase64)



#Please dont look at this ... I should know how Regexes work but nope so get this shit 
$notAfter = (openssl x509 -enddate  -in $CertPath -noout).Split("=")[1]
$fingerprint = (openssl x509 -fingerprint  -in $CertPath -noout).Split("=")[1]
$Issuer = "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3"
$isshash = openssl x509 -issuer_hash  -in $CertPath -noout
$certserial = (openssl x509 -serial -in $CertPath -noout).Split("=")[1]
$name = $certserial 
$keyalg = "rsaEncryption"
$subhash = openssl x509 -subject_hash -in $CertPath -noout
$NotBefore = (openssl x509 -startdate  -in $CertPath -noout).Split("=")[1]
$subject =  (openssl x509 -subject  -in $CertPath -noout).replace("subject=","")
$subject = $subject.Replace(" ","")
$SAN = "DNS:"+ ($subject.Split("=")[1])
$subhash = openssl x509 -subject_hash -in $CertPath -noout
$VNPId = $subject.Replace("CN=","")


$x509Json = 509Body 
if($IsNewCert -eq $true){
          #Upload New 509 and set 509ref
          $Call = $BaseURL + 'objects/ca/meta_x509/'
          $509PostReturn = Invoke-RestMethod -Uri $Call -Method post -Headers $headers -ContentType "application/json" -Body $x509Json
          $509Ref = $509PostReturn._ref        

          $Certjson = CertBody
          $Call = $BaseURL + 'objects/ca/host_key_cert/'
          Invoke-RestMethod -Uri $Call -Method post -Headers $headers -ContentType "application/json" -Body $Certjson  | Out-Null #dont post cert body to log

}else{


    #Get uploaded Certs REF ID# like $Domain
    $Call = $BaseURL + 'objects/ca/meta_x509/'
    $509Object = Invoke-RestMethod -Uri $Call -Method get -Headers $headers -UseBasicParsing      
    $509Object = $509Object| Where-Object {$_.subject -like "$Domain"}  | Sort-Object -Property enddate | Select-Object _ref -First 1
    $509Ref = $509Object._ref

    #Patch the New 509 over the top
    $Call = $BaseURL + 'objects/ca/meta_x509/' + "$509Ref"
    Invoke-RestMethod -Uri $Call -Method patch -Headers $headers -ContentType "application/json" -Body $x509Json 

    ##Get Used by Reference ID#
    $Call = $BaseURL + 'objects/ca/meta_x509/' + "$509Ref/usedby"
    $GetResult = Invoke-RestMethod -Uri $Call -Method get -Headers $headers
    $CertRef = $GetResult.objects 

    $Certjson = CertBody

    #Update the Cert Object 
    $Call = $BaseURL + 'objects/ca/host_key_cert/' + "$CertRef"
    Invoke-RestMethod -Uri $Call -Method patch -Headers $headers -ContentType "application/json" -Body $Certjson | Out-Null #dont post cert body to log

}

