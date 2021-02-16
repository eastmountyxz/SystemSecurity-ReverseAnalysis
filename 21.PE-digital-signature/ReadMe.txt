我们首先需要通过makecert.exe工具生成证书test.cer和私钥文件test.PVK，
接着调用signcode.exe工具对目标PE文件（test.exe）进行数字签名。
通过makecert.exe生成需要的证书常见参数如下：

Error: Invalid algorithm
Usage: MakeCert [ basic|extended options] [outputCertificateFile]
Extended Options
 -sc  <file>         Subject's certificate file
 -sv  <pvkFile>      Subject's PVK file; To be created if not present
 -ic  <file>         Issuer's certificate file
 -ik  <keyName>      Issuer's key container name
 -iv  <pvkFile>      Issuer's PVK file
 -is  <store>        Issuer's certificate store name.
 -ir  <location>     Issuer's certificate store location
                        <CurrentUser|LocalMachine>.  Default to 'CurrentUser'
 -in  <name>         Issuer's certificate common name.(eg: Fred Dews)
 -a   <algorithm>    The signature algorithm
                        <md5|sha1>.  Default to 'md5'
 -ip  <provider>     Issuer's CryptoAPI provider's name
 -iy  <type>         Issuer's CryptoAPI provider's type
 -sp  <provider>     Subject's CryptoAPI provider's name
 -sy  <type>         Subject's CryptoAPI provider's type
 -iky <keytype>      Issuer key type
                        <signature|exchange|<integer>>.
 -sky <keytype>      Subject key type
                        <signature|exchange|<integer>>.
 -d   <name>         Display name for the subject
 -l   <link>         Link to the policy information (such as a URL)
 -cy  <certType>     Certificate types
                        <end|authority|both>
 -b   <mm/dd/yyyy>   Start of the validity period; default to now.
 -m   <number>       The number of months for the cert validity period
 -e   <mm/dd/yyyy>   End of validity period; defaults to 2039
 -h   <number>       Max height of the tree below this cert
 -r                  Create a self signed certificate
 -nscp               Include netscape client auth extension
 -eku <oid[<,oid>]>  Comma separated enhanced key usage OIDs
 -?                  Return a list of basic options
 -!                  Return a list of extended options
