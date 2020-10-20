@echo off
set /P nama="Masukkan nama alias (nama tanpa spasi ex:ekojs)? "
set /P expired="Masukkan masa berlaku sertifikat dalam hari (1 tahun ex:365)? "
set /P pass="Masukkan password anda ? "
echo.
keytool -genkeypair -storepass %pass% -storetype pkcs12 -alias %nama% -validity %expired% -v -keyalg RSA -keysize 2048 -keystore keystore.p12
pause