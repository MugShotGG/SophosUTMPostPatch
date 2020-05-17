function IssueCert{
New-PACertificate $URL -AcceptTOS -Contact $ContactEmail -DnsPlugin DMEasy -PluginArgs $DMEParams -Verbose -PfxPass "$DevPFX" -Force | Out-Null
$CertFolderPath = Get-ChildItem -Directory -Path $env:POSHACME_HOME -Recurse -Filter $URL | select FullName -ExpandProperty FullName
return $CertFolderPath

}

#Gets all x509 Objects 
function Get509Objets{
  
$Call = $BaseURL + 'objects/ca/meta_x509/'
$Return = Invoke-RestMethod -Uri $Call -Method get -Headers $headers 

return $509Objects
}

function Post509Object{
param($Body)  
 
    $Call = $BaseURL + 'objects/ca/meta_x509/'
    $ref =  Invoke-RestMethod -Uri $Call -Method post -Headers $headers -ContentType "application/json" -Body $Body
    $ref = $ref._ref
    Return $ref
}

function PATCH509{
param($509Ref,$Body)  
 
    $Call = $BaseURL + 'objects/ca/meta_x509/' + "$509Ref"
    Invoke-RestMethod -Uri $Call -Method patch -Headers $headers -ContentType "application/json" -Body $Body
}

function GetCertRef{
param($509Ref)  
 
        $Call = $BaseURL + 'objects/ca/meta_x509/' + "$509Ref/usedby"
        $GetResult = Invoke-RestMethod -Uri $Call -Method get -Headers $headers
        $CertRef = $GetResult.objects

    Return $CertRef 
}

function PATCHCert{
param($CertRef,$Body)  
 
    $Call = $BaseURL + 'objects/ca/host_key_cert/' + "$CertRef"
    Invoke-RestMethod -Uri $Call -Method patch -Headers $headers -ContentType "application/json" -Body $Body
}

function PostCertObject{
param($Body)  
  
    $Call = $BaseURL + 'objects/ca/host_key_cert/'
    Invoke-RestMethod -Uri $Call -Method post -Headers $headers -ContentType "application/json" -Body $Body

}
#Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 

#Update URL AND APPLY SOPHOS API TOKEN
$SOPHOSURL = ""
$token = ''

#Configure Sophos Auth
$BaseURL = "https://" + $SOPHOSURL  + ":4444/api/"
$tokenBase64 = [Convert]::ToBase64String([System.Text.Encoding]::Default.GetBytes("token:" + $token))
$headers = @{}
$headers.add("Authorization",'Basic ' + $tokenBase64)


#Get URL You want to issue and upload 
$URL = "*.TheBestDomainsEver.com"


####################################################### ISSUE CERT ###################################
#I'm leveraging PoshAceme to issue the certs and DNSMadeEasy to made the TXT Challenge for validation
#https://github.com/rmbolger/Posh-ACME
#Honestly it doesnt matter which lets encrypt plugin you use but there will be values declared around to suppourt this 
#Defing DNSMadeEasy Vars and PFX PASS
$ContactEmail = ''
$DevPFX = ''
$DMEKey = ''
$DMESecretInsecure =''
$env:POSHACME_HOME = "c:\PoshHome\"

$PWD = ConvertTo-SecureString -String "$DevPFX" -Force -AsPlainText
$DMEParams = @{DMEKey="$DMEKey"; DMESecretInsecure="$DMESecretInsecure"}

$CertFolderPath = IssueCert

#Get Paths to FullChain Cert, Key file, and Cert file from the cert we just issued
$PFXPath = $CertFolderPath + "\fullchain.pfx"
$KeyPath = $CertFolderPath + "\cert.key"
$CertPath = $CertFolderPath + "\cert.cer"
     
$CertContent = (Get-Content $CertPath) | Out-String
$KeyContent = (Get-Content $KeyPath) | Out-String
$CertAsText = openssl x509 -in $CertPath -noout -text | Out-String
$509Format = "$CertAsText" + "$CertContent"

#It Doesnt matter what provider you use as long as you can feed the rest of this script the above7 values
################################################################################################

#Youll need to upload the Lets Encrypt Root cert and get its REF. Not a great way to show that programtically 
#Download here https://letsencrypt.org/certs/isrgrootx1.pem.txt
$CA = "REF_CaVerLetsEncryCa"


#Get Any existing 509 objects
$509Objects = Get509Objets

$509Object = $509Objects | Where-Object {$_.subject -like $URL}


if(($509Object.count) -eq 0){
#IF you have any rules on the server that reference this cert its prefered to PATCH so that they just pick up your new cert
#But if you want to issue a new one then reference it in a rule we will need POST Atleast for the first time we do it 
        
        #I'm not proud of this. If you have any skill at REGEX I recomend you use that to parse this info but i dont sooo...
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

    
    #Youll need the reference ID of the 509 object you just made when you post the Cert and KEY to it 
    $509Ref = Post509Object $x509Json

        $body =  [ordered]@{
            name= "$VNPId"
            ca= "$CA"
            certificate= "$509Format"
            comment= "AutomatedTM"
            encrypted= $false
            key= "$KeyContent"
            meta= "$509Ref"
     }
        $CertJson = ConvertTo-Json $body
 

 PostCertObject $CertJson

}Else
{
#There is a 509 to PATCH
        
        #Pull the 509Ref ID From the Response body we got
        $509Ref = $509Object._ref



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
    
    #Update the existing 509 object with these values
    PATCH509 $509Ref $x509Json

    $CertRef = GetCertRef $509Ref


    $body =  [ordered]@{
        name= "$VNPId"
        ca= "$CA"
        certificate= "$509Format"
        comment= "AutomatedTM"
        encrypted= $false
        key= "$KeyContent"
        meta= "$509Ref"
     }
        $CertJson = ConvertTo-Json $body

    #Update the Existing CERT Object
    PATCHCert $CertRef $CertJson

}     
