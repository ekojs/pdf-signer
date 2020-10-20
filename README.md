## PDF Signer Version 1.0.0
### Author Eko Junaidi Salam <eko.junaidi.salam@gmail.com>

Seluruh perubahan dalam proyek ini ada pada [CHANGELOG](https://github.com/ekojs/pdf-signer/blob/master/CHANGELOG.md)

Format changelog berdasarkan [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
dan proyek ini mengikuti standar [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

### Cara melakukan generate Asymmetric Public Key Infrastructure (PKI)
Generate PKCS1 private key menggunakan openssl
```
openssl genrsa -out private.pem 2048
```

### Pilihan Format Key pada Private Key
Generate (PKCS#8, DER) format:
```
openssl pkcs8 -topk8 -in private.pem -outform DER -out private.der -nocrypt
```

Generate (PKCS#8, PEM) format:
```
openssl pkcs8 -topk8 -in private.pem -outform PEM -out private8.pem -nocrypt
```

### Pilihan Format Key pada Public Key
Generate public key (PKCS#8, DER) format dari private key:
```
openssl rsa -in private.pem -pubout -outform DER -out public.der
```

Generate public key (PKCS#8, PEM) format dari private key:
```
openssl rsa -in private.pem -pubout -outform PEM -out public.pem
```

### Penggunaan keytool dari java
Generate Self Signed Key Pair PCKS#12 menggunakan keytool
```
keytool -genkeypair -storepass 123456 -storetype pkcs12 -alias test -validity 365 -v -keyalg RSA -keysize 2048 -keystore keystore.p12
```

Import PCKS#12 file to keystore java menggunakan keytool
```
keytool -importkeystore -srckeystore keystore.p12 -srcstoretype PKCS12 -destkeystore whatever.store -deststoretype PKCS12
```

Import Certificate X509 to keystore menggunakan keytool
```
keytool -importcert -keystore whatever.store -alias test -file cert.crt
```

Silahkan kunjungi [Link Berikut](https://github.com/ekojs/digital_signature), untuk mempelajari operasi - operasi konsole openssl.

### Compile Source secara manual
Prasyarat minimum kompilasi:
```
1. Install Oracle JDK version >= 11.
2. Setup Environments Path JAVA_HOME folder.
3. Cek versi java.
    java -version
4. Cek versi java compiler.
    javac -version
```

Compile source menggunakan Linux:
```
sh build.sh
```

Compile source menggunakan Windows:
```
start build.bat
```

Konfigurasi ```res/params.json``` sesuai kebutuhan

Menjalankan program:
```
cd dist/
java -jar pdf_signer.jar
```
