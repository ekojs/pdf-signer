/*
 * The MIT License
 *
 * Copyright 2020 Eko Junaidi Salam eko.junaidi.salam@gmail.com.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package egen;

import digsig.PDFSigner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.apache.commons.codec.binary.Base64;
import javax.swing.JOptionPane;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * FileEncryption Class for utilize digital signature
 * 
 * @author Eko Junaidi Salam eko.junaidi.salam@gmail.com
 */
public class FileEncryption {
    
    /**
     * Define constant for Charset
     */
    public static final String Charset = "UTF-8";
    
    /**
     * Define constant for Signature Instance
     */
    public static final String signature_instance = "SHA256withRSA";
    
    /**
     * Define constant for RSA Key Size in bits
     */
    public static final int RSA_Key_Size = 2048;

    /**
     * Creates and setup instances for cipher
     */
    public FileEncryption() {
        
    }
    
    /**
     * Load Keystore with format PKCS12
     * Create Keystore using keytool from java, for example :
     * 
     * {@code keytool -genkeypair -storepass 123456 -storetype pkcs12 -alias test -validity 365 -v -keyalg RSA -keystore keystore.p12 }
     * 
     * @param keystore for full path keystore File
     * @param pin for keystore password
     * @return KeyStore
     */
    public KeyStore loadKeystore(File keystore, String pin){
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(keystore),pin.toCharArray());
            
            return ks;
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            System.out.println(getClass().getName()+" loadKeystore : "+ex);
            JOptionPane.showMessageDialog(null, getClass().getName()+" loadKeystore : "+ex);
        }
        return null;
    }
    
    /**
     * Create Keystore for new user
     * 
     * Inspiration from : 
     * https://stackoverflow.com/questions/50798547/java-p12-generation-from-a-existing-keys
     * https://www.programcreek.com/java-api-examples/?code=YMCoding/kafka-0.11.0.0-src-with-comment/kafka-0.11.0.0-src-with-comment-master/clients/src/test/java/org/apache/kafka/test/TestSslUtils.java
     * 
     * @param outFile path file
     * @param alias name for keystore
     * @param cn CommonName in Certificate
     * @param pin passphrase for PKCS12 Keystore
     * @return KeyStore
     */
    public static KeyStore createKeystore(String outFile, String alias, String cn,String pin){
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("PKCS12");
            ks.load(null,pin.toCharArray());
            
            KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(RSA_Key_Size);
            KeyPair pair = keygen.generateKeyPair();
            
            X509Certificate[] certs = new X509Certificate[1];
            certs[0] = createSelfSigned(pair, cn, 0);
            
            ks.setKeyEntry(alias, pair.getPrivate(), pin.toCharArray(), certs);
            try (FileOutputStream fos = new FileOutputStream(outFile)) {
                ks.store(fos,pin.toCharArray());
                fos.close();
            }
            
            // Test Keystore
            if(Files.exists(Paths.get(outFile))){
                ks = KeyStore.getInstance("PKCS12");
                try (FileInputStream fis = new FileInputStream(outFile)) {
                    ks.load(fis, pin.toCharArray());
                    fis.close();
                }
            }
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException ex) {
            System.out.println("createKeystore : "+ex);
            JOptionPane.showMessageDialog(null,"createKeystore : "+ex);
        }
        return ks;
    }
    
    /**
     * Create Self Signed X509 Certificate
     * @param pair KeyPair Generator
     * @param dname Distinguished Name for CN in X509 Certificate
     * @param days Days expiring
     * @return X509Certificate 
     */
    private static X509Certificate createSelfSigned(KeyPair pair,String dname,int days){
        X509Certificate cert = null;
        try{
            if(isNullOrEmpty(dname)){
                dname = "C=ID, ST=DKI Jakarta, L=Jakarta Selatan,"
                    + " O=EJSStudio, OU=Digital Signature, CN="+PDFSigner.appName+" v"+PDFSigner.appVersion;
            }else{
                dname = "C=ID, ST=DKI Jakarta, L=Jakarta Selatan,"
                    + " O=EJSStudio, OU="+PDFSigner.appName+" v"+PDFSigner.appVersion +", CN="+dname;
            }
            
            if(days <= 0){
                days = 730;
            }
            
            X500Name dn = new X500Name(dname);
            BigInteger sn = new BigInteger(64, new SecureRandom());
            Date from = new Date();
            Date to = new Date(from.getTime() + days * 86400000L);
            
            ContentSigner cs = new JcaContentSignerBuilder("SHA256WithRSA").build(pair.getPrivate());
            JcaX509v3CertificateBuilder cb = new JcaX509v3CertificateBuilder(dn, sn, from, to, dn, pair.getPublic());
            cert = new JcaX509CertificateConverter().getCertificate(cb.build(cs));
        }catch(CertificateException | OperatorCreationException ex){
            System.out.println("createSelfSigned : "+ex);
            JOptionPane.showMessageDialog(null, "createSelfSigned : "+ex);
        }
        return cert;
    }
    
    /**
     * Add X509 Certificate in KeyStore file
     * @param keystoreFile
     * @param certFile
     * @param alias
     * @param pin 
     */
    public static void addCert(File keystoreFile,File certFile, String alias, String pin){
        try{
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(new FileInputStream(keystoreFile),pin.toCharArray());
            
            X509Certificate cert = loadCertificate(certFile);
            cert.checkValidity();
            SigUtils.checkCertificateUsage(cert);
            TrustedCertificateEntry ce = new TrustedCertificateEntry(cert);
            ProtectionParameter pp = new PasswordProtection(null);
            ks.setEntry(alias, ce, pp);
            
            try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
                ks.store(fos, pin.toCharArray());
                fos.close();
            }
        }catch(IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException ex){
            System.out.println("addCert : "+ex);
            JOptionPane.showMessageDialog(null, "addCert : "+ex);
        }
    }
    
    /**
     * Signed PDF File using key store
     * @param pdfFile
     * @param keystore
     * @param alias
     * @param pin
     * @param reason 
     * @param tsaUrl 
     * @param tsaUsername 
     * @param tsaPassword 
     */
    public void signPDF(File pdfFile,KeyStore keystore, String alias, String pin, String reason, String tsaUrl, String tsaUsername, String tsaPassword){
        try{
            // sign PDF
            PDFSignature signing = new PDFSignature(keystore, alias, pin.toCharArray());

            // Get Common Name from certificate
            X509Certificate cert = (X509Certificate) keystore.getCertificate(alias);
            X500Name dn = new JcaX509CertificateHolder(cert).getSubject();
            RDN cn = dn.getRDNs(BCStyle.CN)[0];
            RDN loc = dn.getRDNs(BCStyle.L)[0];
            
            String name = pdfFile.getName();
            String substring = name.substring(0, name.lastIndexOf('.'));

            File outFile = new File(pdfFile.getParent(), substring + "_signed.pdf");
            signing.setAuthorName(IETFUtils.valueToString(cn.getFirst().getValue()));
            signing.setLocation(IETFUtils.valueToString(loc.getFirst().getValue()));
            signing.setReason(reason);
            signing.setTsaUrl(tsaUrl);
            signing.setTsaUsername(tsaUsername);
            signing.setTsaPassword(tsaPassword);
            signing.signDetached(pdfFile, outFile);
            System.out.println("PDF File "+ pdfFile.getName() +" Signed");
        }catch(KeyStoreException | CertificateEncodingException ex){
            System.out.println(getClass().getName()+" signPDF : "+ex);
            JOptionPane.showMessageDialog(null, getClass().getName()+" signPDF : "+ex);
        }
    }
    
    /**
     * Extract X509 Certificate from KeyStore
     * @param ks
     * @param alias
     * @return Boolean
     */
    public boolean extractCert(KeyStore ks, String alias){
        try{
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            X500Name dn = new JcaX509CertificateHolder(cert).getSubject();
            RDN cn = dn.getRDNs(BCStyle.CN)[0];
            String certName = IETFUtils.valueToString(cn.getFirst().getValue());
            String certFile = "cert_"+DigestUtils.sha256Hex(certName)+".pem";
            try (FileOutputStream fos = new FileOutputStream(certFile)) {
                fos.write("-----BEGIN CERTIFICATE-----\n".getBytes(Charset));
                fos.write(Base64.encodeBase64(cert.getEncoded()));
                fos.write("\n-----END CERTIFICATE-----".getBytes(Charset));
                fos.close();
            }
            if(Files.exists(Paths.get(certFile)) && Files.size(Paths.get(certFile)) > 500){
                System.out.println("Certificate exported");
                return true;
            }
        }catch(IOException | KeyStoreException | CertificateEncodingException ex){
            System.out.println(getClass().getName()+" extractCert : "+ex);
            JOptionPane.showMessageDialog(null, getClass().getName()+" extractCert : "+ex);
        }
        return false;
    }
    
    /**
     * Extract Private Key from KeyStore
     * @param ks
     * @param alias
     * @param pin
     * @return Boolean
     */
    public boolean extractKey(KeyStore ks, String alias, String pin){
        try{
            X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
            X500Name dn = new JcaX509CertificateHolder(cert).getSubject();
            RDN cn = dn.getRDNs(BCStyle.CN)[0];
            String certName = IETFUtils.valueToString(cn.getFirst().getValue());
            String keyFile = "priv_"+DigestUtils.sha256Hex(certName)+".pem";
            
            try (FileOutputStream fos = new FileOutputStream(keyFile)) {
                fos.write("-----BEGIN PRIVATE KEY-----\n".getBytes(Charset));
                fos.write(Base64.encodeBase64(ks.getKey(alias,pin.toCharArray()).getEncoded()));
                fos.write("\n-----END PRIVATE KEY-----".getBytes(Charset));
                fos.close();
            }
            if(Files.exists(Paths.get(keyFile)) && Files.size(Paths.get(keyFile)) > 500){
                System.out.println("Private Key exported");
                return true;
            }
        }catch(IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | CertificateEncodingException ex){
            System.out.println(getClass().getName()+" extractKey : "+ex);
            JOptionPane.showMessageDialog(null, getClass().getName()+" extractKey : "+ex);
        }
        return false;
    }
    
    /**
     * Load X509 Certificate from file
     * @param certFile
     * @return 
     */
    public static X509Certificate loadCertificate(File certFile){
        X509Certificate cert = null;
        try{
            // read certificate key
            FileInputStream baca;
            baca = new FileInputStream(certFile);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = (X509Certificate) cf.generateCertificate(baca);
            baca.close();
        }catch(IOException | CertificateException ex){
            System.out.println("loadCertificate : "+ex);
            JOptionPane.showMessageDialog(null, "loadCertificate : "+ex);
        }
        return cert;
    }
    
    /**
     * Write byte[] data to a file
     * @param path String full path file output
     * @param key byte[] data to be wrote
     * @return boolean
     */
    public boolean writeToFile(String path, byte[] key){
        File f = new File(path);
        try (FileOutputStream fos = new FileOutputStream(f)) {
            fos.write(key);
            fos.flush();
            if(Files.exists(Paths.get(path))){
                return true;
            }
        }catch (Exception ex){
            System.out.println(getClass().getName()+" writeToFile : "+ex);
            JOptionPane.showMessageDialog(null, getClass().getName()+" writeToFile : "+ex);
        }
        return false;
    }

    /**
     * Copies a stream.
     * @param is InputStream
     * @param os OutputStream
     */
    private void copy(InputStream is, OutputStream os) {
        try{
            int i;
            byte[] b = new byte[1024];
            while((i=is.read(b))!=-1) {
                os.write(b, 0, i);
            }
        }catch (IOException ex){
            System.out.println(getClass().getName()+" copy : "+ex);
            JOptionPane.showMessageDialog(null, getClass().getName()+" copy : "+ex);
        }
    }
    
    /**
     * Check is null or empty string
     * @param str
     * @return boolean
     */
    public static boolean isNullOrEmpty(String str) {
        if(str != null && !str.isEmpty())
            return false;
        return true;
    }
}
