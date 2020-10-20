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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.X509Certificate;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Eko Junaidi Salam eko.junaidi.salam@gmail.com
 */
public class FileEncryptionTest {
    private static final String inDir = "test/resources/";
    private static final String outDir = "build/test/results/";
    private static final String keystorePath = inDir + "digsig.store";
    private static final String keyPath = "key_vault/";
    
    private static final String privFile = "priv_40c7f58632fa0ec8485090fa04a186744b3773f6f9c57d19dfa7bbe4489203f3.der";
    private static final String privEncFile = "priv_40c7f58632fa0ec8485090fa04a186744b3773f6f9c57d19dfa7bbe4489203f3.der.enc";
    private static final String pubFile = "pub_40c7f58632fa0ec8485090fa04a186744b3773f6f9c57d19dfa7bbe4489203f3.der";
    private static final String certFile = "cert_15abbdc5727989f0ac19b3233b5726c166fe1c00ab502dd096dc9f4a0bec67a6.pem";
    private static final String pdfFile = "sign_me.pdf";
    
    private static String alias = "digsig";
    private static String password = "123456";
    private static FileEncryption fe;
    private static CertificateHolder ch;
    
    public FileEncryptionTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
        new File(outDir).mkdirs();
        fe = new FileEncryption();
    }
    
    @AfterClass
    public static void tearDownClass() throws IOException {
        Files.deleteIfExists(Paths.get(keyPath+privFile));
        Files.deleteIfExists(Paths.get(keyPath+privEncFile));
        Files.deleteIfExists(Paths.get(keyPath+pubFile));
        Files.deleteIfExists(Paths.get(certFile));
        Files.deleteIfExists(Paths.get("priv_15abbdc5727989f0ac19b3233b5726c166fe1c00ab502dd096dc9f4a0bec67a6.pem"));
    }

    /**
     * Test of loadKeystore method, of class FileEncryption.
     * @throws java.security.KeyStoreException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.UnrecoverableKeyException
     */
    @Test
    public void testLoadKeystore() throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        System.out.println("loadKeystore");
        KeyStore ks = fe.loadKeystore(new File(keystorePath), password);
        ch = CertificateHolder.getInstance();
        ch.setCert((X509Certificate) ks.getCertificate(alias));
        assertEquals("PKCS#8",((PrivateKey) ks.getKey(alias, password.toCharArray())).getFormat());
        assertEquals("EJSStudio",ch.getOrganization());
        
        // Extract certificate
        System.out.println("extractCert");
        fe.extractCert(ks, alias);
        assertTrue(Files.exists(Paths.get(certFile)));
        
        // Extract private key
        System.out.println("extractKey");
        fe.extractKey(ks, alias, password);
        assertTrue(Files.exists(Paths.get("priv_15abbdc5727989f0ac19b3233b5726c166fe1c00ab502dd096dc9f4a0bec67a6.pem")));
        
        // Load certificate
        System.out.println("loadCertificate");
        assertEquals("X.509",FileEncryption.loadCertificate(new File(certFile)).getPublicKey().getFormat());
        
        
        // Generate another cert
        System.out.println("addCert");
        KeyStore another = FileEncryption.createKeystore(outDir+"ekojs.store", "ekojs", "Eko Junaidi Salam", password);
        X509Certificate ecert = (X509Certificate) another.getCertificate("ekojs");
        
        // Add Cert
        FileEncryption.addCert(new File(outDir+"ekojs.store"), new File(certFile), alias, password);
        another = fe.loadKeystore(new File(outDir+"ekojs.store"), password);
        ch = CertificateHolder.getInstance();
        ch.setCert((X509Certificate) another.getCertificate(alias));
        assertEquals("Digital Signature",ch.getName());
        ch.setCert((X509Certificate) another.getCertificate("ekojs"));
        assertEquals("Eko Junaidi Salam",ch.getName());
    }

    /**
     * Test of signPDF method, of class FileEncryption.
     * @throws java.io.IOException
     */
    @Test
    public void testSignPDF() throws IOException {
        System.out.println("signPDF");
        KeyStore ks = fe.loadKeystore(new File(keystorePath), password);
        File pdf = new File(inDir+pdfFile);
        fe.signPDF(pdf, ks, alias, password, "Created and signed");
        assertTrue(Files.exists(Paths.get(pdf.getParent()+"/sign_me_signed.pdf")));
        Files.deleteIfExists(Paths.get(pdf.getParent()+"/sign_me_signed.pdf"));
    }
}
