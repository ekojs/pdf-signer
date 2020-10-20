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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author Eko Junaidi Salam eko.junaidi.salam@gmail.com
 */
public class CertificateHolderTest {
    private static final String password = "123456";
    private static final String res = "test/resources/digsig.store";
    private static final String alias = "digsig";
    private static CertificateHolder ch;
    private static X509Certificate cert;
    private static KeyStore ks;
    
    public CertificateHolderTest() {
    }
    
    @BeforeClass
    public static void setUpClass() throws FileNotFoundException, 
            KeyStoreException, IOException, NoSuchAlgorithmException, 
            CertificateException {
        ks = KeyStore.getInstance("PKCS12");
        ks.load(new FileInputStream(res),password.toCharArray());
        cert = (X509Certificate) ks.getCertificate(alias);
    }
    
    @AfterClass
    public static void tearDownClass() {
        ks = null;
        cert = null;
        ch = null;
    }

    /**
     * Test of getInstance method, of class CertificateHolder.
     */
    @Test
    public void testGetInstance() {
        System.out.println("Testing getInstance...");
        ch = CertificateHolder.getInstance();
        assertTrue(ch instanceof CertificateHolder);
        
        ch.setCert(cert);
        assertTrue(cert != null);
        assertEquals("Digital Signature",ch.getName());
//        assertEquals(Digsig.appName+" v"+Digsig.appVersion,ch.getUnit());
        assertEquals("EJSStudio",ch.getOrganization());
        assertEquals("Jakarta Selatan",ch.getLocation());
        assertEquals("DKI Jakarta",ch.getState());
        assertEquals("ID",ch.getCountry());
    }
    
    /**
     * Test of setCert
     */
    @Test (expected = NullPointerException.class)
    public void testSetCert(){
        ch = CertificateHolder.getInstance();
        X509Certificate c = null;
        ch.setCert(c);
    }
}
