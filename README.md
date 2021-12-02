# java-https-cert-util
Console tool to import https page certificates to java certificate store automatically

usage: 


`  mvn spring-boot:run -Dspring-boot.run.arguments="google.es"
`
or

`java -jar java-https-cert-import-1.0.0.jar google.es`

if you have problems whit the KeyStore password:

`  mvn spring-boot:run -Dspring-boot.run.arguments="google.es" password
`
or

`java -jar java-https-cert-import-1.0.0.jar google.es` password

















Thanks to:

https://github.com/escline/InstallCert