[CmdletBinding()]
Param(
   [Parameter(Mandatory=$true,Position=1)] [string] $StorageAccountName,
   [Parameter(Mandatory=$True,Position=2)] [string] $AccessKey,
   [Parameter(Mandatory=$True,Position=3)] [string] $FilesystemName,
   [Parameter(Mandatory=$True,Position=4)] [string] $Path
)
#In StorageAccountName parameter: The name of the storage account where the Datalake Gen2 is located
#In AccessKey parameter: The Storage Account access key
#In FileSystemName parameter : The name of the DL Blob container
#In Path parameter:
#   If you want get permission for filesystem just use “/”.
#   If you want to get permissions for a given path use it without leading “/” in.ex.: “Folder1/Folder2/File.csv”

Write-Host 'Connecting to Azure...'
az login

Write-Host 'Connecting to Storage Account...'

# Rest documentation:
# https://docs.microsoft.com/en-us/rest/api/storageservices/datalakestoragegen2/path/getproperties


$date = [System.DateTime]::UtcNow.ToString("R") # ex: Sun, 10 Mar 2019 11:50:10 GMT
 
$n = "`n"
$method = "HEAD"
 
$stringToSign = "$method$n" #VERB
$stringToSign += "$n" # Content-Encoding + "\n" +  
$stringToSign += "$n" # Content-Language + "\n" +  
$stringToSign += "$n" # Content-Length + "\n" +  
$stringToSign += "$n" # Content-MD5 + "\n" +  
$stringToSign += "$n" # Content-Type + "\n" +  
$stringToSign += "$n" # Date + "\n" +  
$stringToSign += "$n" # If-Modified-Since + "\n" +  
$stringToSign += "$n" # If-Match + "\n" +  
$stringToSign += "$n" # If-None-Match + "\n" +  
$stringToSign += "$n" # If-Unmodified-Since + "\n" +  
$stringToSign += "$n" # Range + "\n" + 
$stringToSign +=    
                    <# SECTION: CanonicalizedHeaders + "\n" #>
                    "x-ms-date:$date" + $n + 
                    "x-ms-version:2018-11-09" + $n # 
                    <# SECTION: CanonicalizedHeaders + "\n" #>
 
$stringToSign +=    
                    <# SECTION: CanonicalizedResource + "\n" #>
                    "/$StorageAccountName/$FilesystemName/$Path" + $n + 
                    "action:getAccessControl" + $n +
                    "upn:true"# 
                    <# SECTION: CanonicalizedResource + "\n" #>
 
$sharedKey = [System.Convert]::FromBase64String($AccessKey)
$hasher = New-Object System.Security.Cryptography.HMACSHA256
$hasher.Key = $sharedKey
 
$signedSignature = [System.Convert]::ToBase64String($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($stringToSign)))
 
 
$authHeader = "SharedKey ${StorageAccountName}:$signedSignature"
 
$headers = @{"x-ms-date"=$date} 
$headers.Add("x-ms-version","2018-11-09")
$headers.Add("Authorization",$authHeader)

$URI = "https://$StorageAccountName.dfs.core.windows.net/" + $FilesystemName + "/" + $Path + "?action=getAccessControl&upn=true"

Write-Host 'Getting ACLs...'
$result = Invoke-WebRequest -method $method -Uri $URI -Headers $headers

Write-Host 'Searching Groups...'
$guids=[regex]::Matches($result.Headers.'x-ms-acl' -split ",",'group:\w{8}-\w{4}-\w{4}-\w{4}-\w{12}')

Write-Host 'Getting group(s) guid and name...'
foreach ($element in $guids) {
  $element.Value.Substring(6,36)
  az ad group show --group $element.Value.Substring(6,36) --query displayName -o json
}