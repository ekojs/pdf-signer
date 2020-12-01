/*
 * Copyright 2015 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package egen;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import javax.swing.JOptionPane;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

/**
 * @author PDFBox
 */
public class SignatureBase implements SignatureInterface {
    private PrivateKey privateKey;
    private Certificate[] certificateChain;
    private X509Certificate x509cert;
    private String tsaUrl;
    private String tsaUsername = null;
    private String tsaPassword = null;
    
    
    /**
     * Initialize the signature creator with a keystore (pkcs12) and pin that should be used for the
     * signature.
     *
     * @param alias
     * @param keystore is a pkcs12 keystore.
     * @param pin is the pin for the keystore / private key
     */
    public SignatureBase(KeyStore keystore, String alias, char[] pin){
        try {
            Certificate cert = null;
            
            setPrivateKey((PrivateKey) keystore.getKey(alias, pin));
            Certificate[] certChain = keystore.getCertificateChain(alias);
            if (certChain != null){
                setCertificateChain(certChain);
                cert = certChain[0];
                if (cert instanceof X509Certificate){
                    // avoid expired certificate
                    ((X509Certificate) cert).checkValidity();

                    SigUtils.checkCertificateUsage((X509Certificate) cert);
                }
            }

            if (cert == null){
                throw new IOException("Could not find certificate");
            }
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | 
                CertificateExpiredException | CertificateNotYetValidException | CertificateParsingException ex) {
            System.out.println("SignatureBase : "+ex);
            JOptionPane.showMessageDialog(null, "SignatureBase : "+ex);
        }
        
    }

    /**
     * Set Private Key
     * @param privateKey 
     */
    public final void setPrivateKey(PrivateKey privateKey)
    {
        this.privateKey = privateKey;
    }

    /**
     * Set Certificate Chain
     * @param certificateChain 
     */
    public final void setCertificateChain(final Certificate[] certificateChain)
    {
        this.certificateChain = certificateChain;
    }

    /**
     * Get Certificate Chain
     * @return 
     */
    public Certificate[] getCertificateChain()
    {
        return certificateChain;
    }
    
    public void setTsaUrl(String tsaUrl)
    {
        this.tsaUrl = tsaUrl;
    }
    
    public void setTsaUsername(String tsaUsername)
    {
        this.tsaUsername = tsaUsername;
    }
    
    public void setTsaPassword(String tsaPassword)
    {
        this.tsaPassword = tsaPassword;
    }

    /**
     * Sign PDF File
     * @param content
     * @return
     * @throws IOException 
     */
    @Override
    public byte[] sign(InputStream content) throws IOException {
        try{
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            X509Certificate cert = (X509Certificate) certificateChain[0];
            ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder()
                    .build()).build(sha1Signer, cert));
            gen.addCertificates(new JcaCertStore(Arrays.asList(certificateChain)));
            CMSProcessableInputStream msg = new CMSProcessableInputStream(content);
            CMSSignedData signedData = gen.generate(msg, false);
            
            if (tsaUrl != null && tsaUrl.length() > 0){
                ValidationTimeStamp validation = new ValidationTimeStamp(tsaUrl,tsaUsername,tsaPassword);
                signedData = validation.addSignedTimeStamp(signedData);
            }
            
            return signedData.getEncoded();
        }catch (GeneralSecurityException | CMSException | OperatorCreationException e){
            throw new IOException(e);
        }
    }

    private void setCertificate(X509Certificate cert) {
        this.x509cert = cert;
    }

    /**
     * Get X509 Certificate
     * @return 
     */
    public X509Certificate getX509cert() {
        return x509cert;
    }
}
