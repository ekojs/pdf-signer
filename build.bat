@echo off

REM Compiling Source
REM Program: build.bat
REM Author : Eko Junaidi Salam <eko.junaidi.salam@gmail.com>
REM Version: 1.0.0
REM License: MIT

echo Clean Up Build Folder...
rd /S /Q build
rd /S /Q dist

echo Compile and Creating distribution in progress...
mkdir build\classes
mkdir dist
mkdir dist\lib dist\res dist\dokumen

javac -Xlint:deprecation -d .\build\classes -cp .\lib\* src\digsig\*.java src\egen\*.java src\model\*.java src\tampilan\*.java
echo Manifest-Version: 1.0 > MANIFEST
echo Ant-Version: Apache Ant 1.9.7 >> MANIFEST
echo Created-By: 1.8.0_201-b09 (Oracle Corporation) >> MANIFEST
echo Class-Path: lib/gson-2.8.6.jar lib/commons-codec-1.11.jar lib/commons-logging-1.2.jar lib/pdfbox-2.0.19.jar lib/bcprov-jdk15on-165.jar lib/bcpkix-jdk15on-165.jar lib/fontbox-2.0.19.jar >> MANIFEST
echo Main-Class: digsig.PDFSigner >> MANIFEST

jar cvmf MANIFEST dist\pdf_signer.jar -C build/classes/ .
copy lib dist\lib
copy res dist\res
copy *.md dist
copy *.TXT dist
copy *.bat dist
copy LICENSE dist
del  MANIFEST

echo Compile finished...
pause
