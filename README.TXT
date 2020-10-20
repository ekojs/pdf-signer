Untuk menggunakan aplikasi ini anda wajib menginstall java jdk, cek java:

1. Dobel klik file cek_java.bat
2. Akan muncul konsole informasi, bila tidak ada error maka komputer anda sudah terinstall java

Silahkan download bila belum memiliki java jdk pada link berikut:
https://www.oracle.com/java/technologies/javase-jdk8-downloads.html

Membuat sertifikat digital (self signed certificate):

1. Dobel klik file buat_sertifikat.bat
2. Isiikan seluruh pertanyaan
3. Sertifikat telah dibuat

Membuat sertifikat digital (self signed certificate) secara konsol:

keytool -genkeypair -storepass password_anda -storetype pkcs12 -alias alias_anda_tanpa_spasi -validity masa_berlaku_dalam_hari -v -keyalg RSA -keysize 2048 -keystore keystore.p12

contoh : 
keytool -genkeypair -storepass 123456 -storetype pkcs12 -alias test -validity 365 -v -keyalg RSA -keysize 2048 -keystore keystore.p12


Cara menggunakan aplikasi signer :

1. Pastikan file pdf telah disimpan pada folder dokumen.
2. Sesuaikan parameter pada file params.json, sesuai alias dan reason anda. Untuk alias sesuaikan pada saat membuat sertifikat digital.
3. Dobel klik file signer.bat
4. Masukkan password sertifikat digital anda.
5. Dokumen telah selesai di tanda tangani, cek file *_signed.pdf pada folder dokumen anda.

Cara menjalankan aplikasi melalui konsol :

java -jar "pdf_signer.jar"

Melihat bantuan :

java -jar "pdf_signer.jar" -h
