$pass = ConvertTo-SecureString -string "PASSWORD" -AsPlainText -Force  ##F5 Password
    
$f5Cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList "admin", $pass  ### F5 USER

$F5_IP = '1.1.1.1'  ## F5 IP

$path = "C:\temp\vs.csv" ## Path to save the CSV report

$expired_array = @()

$VS_array = @()

$unix_timestamp_now = [int][double]::Parse((Get-Date -UFormat %s))
try {
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@ }
catch {
    pass
}

[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

$sslProfilesClient = (Invoke-RestMethod -Method GET -Uri "https://$F5_IP/mgmt/tm/ltm/profile/client-ssl" -Credential $f5Cred).items

$virtualServers = Invoke-RESTMethod -Method GET -Uri "https://$F5_IP/mgmt/tm/ltm/virtual?expandSubcollections=true&`$select=name,partitioclsn,fullPath,profilesReference" -Credential $f5Cred


foreach($cert_profile in $sslProfilesClient){

    $url = ($cert_profile.certreference.link).replace('localhost',$F5_IP)

    $cert_file = Invoke-RestMethod -Method GET -Uri $url -Credential $f5Cred

    if ($cert_file.expirationDate -lt $unix_timestamp_now){
                
            $SSL_Object = New-Object PSObject
            $SSL_Object | add-member Noteproperty CertProfile $cert_profile.name
            $SSL_Object | add-member Noteproperty CertFile $cert_file.name
            $SSL_Object | add-member Noteproperty fullPath $cert_profile.fullPath
            $SSL_Object | add-member Noteproperty CertExpiry $cert_file.expirationString
        
        $expired_array += $SSL_Object
    }
    }

foreach($virtualserver in $virtualservers.items){
    foreach ($cert in $expired_array){

        if($virtualserver.profilesReference.items.fullPath -eq $cert.fullPath -and $virtualserver.profilesReference.items.namereference.link -match 'client-ssl'){
                
            $VS_Object = New-Object PSObject
            $VS_Object | add-member Noteproperty CertProfile $cert.CertProfile
            $VS_Object | add-member Noteproperty CertFile $cert.CertFile
            $VS_Object | add-member Noteproperty VirtualServer $virtualserver.name
            $VS_Object | add-member Noteproperty CertExpiry $cert.CertExpiry

            $VS_array += $VS_Object
 
        }
    }
    }
               
        

    
    



$VS_array | select CertProfile,CertFile,VirtualServer,CertExpiry | export-csv -Path $path
