#!/bin/bash

# Compiling Source
# Program: build.sh
# Author : Eko Junaidi Salam <eko.junaidi.salam@gmail.com>
# Version: 1.0.0
# License: MIT

export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export endc=$'\e[0m'

printf "${white}%s${endc} ${blue}%s${endc}\n" "clean  :" "Clean Up Build Folder..."
rm -rf build/
rm -rf dist/

printf "${white}%s${endc} ${blue}%s${endc}\n" "compile:" "Compile and Creating distribution in progress..."
mkdir -p build/classes
mkdir -p dist/{lib,res,dokumen}

javac -Xlint:deprecation -d build/classes/ -cp ".:lib/*" src/*/*.java
cat << EOF > MANIFEST
Manifest-Version: 1.0
Ant-Version: Apache Ant 1.9.7
Created-By: 1.8.0_201-b09 (Oracle Corporation)
Class-Path: lib/gson-2.8.6.jar lib/commons-codec-1.11.jar lib/commons-logging-1.2.jar lib/pdfbox-2.0.21.jar lib/bcprov-jdk15on-165.jar lib/bcpkix-jdk15on-165.jar lib/fontbox-2.0.21.jar
Main-Class: digsig.PDFSigner
EOF

jar cvmf MANIFEST dist/pdf_signer.jar -C build/classes/ .
cp -pR lib/* dist/lib/
cp -pR res/* dist/res/
cp -pR *.{md,TXT} dist/
cp -pR *.bat dist/
cp -pR LICENSE dist/
rm -f MANIFEST

#zip -r pdf_signer.zip dist/
printf "${white}%s${endc} ${green}%s${endc}\n" "status :" "Compile finished..."
