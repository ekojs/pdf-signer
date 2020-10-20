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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.util.Calendar;
import javax.swing.JOptionPane;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;

/**
 *
 * @author Eko Junaidi Salam eko.junaidi.salam@gmail.com
 */
public class PDFSignature extends SignatureBase {
    String authorName = PDFSigner.appName + " v"+PDFSigner.appVersion;
    String location = "Jakarta";
    String reason = "Approved";

    /**
     * Set Author Name for Signed PDF
     * @param authorName 
     */
    public void setAuthorName(String authorName) {
        this.authorName = authorName;
    }

    /**
     * Set Location for Signed PDF
     * @param location 
     */
    public void setLocation(String location) {
        this.location = location;
    }

    /**
     * Set Reason for signed PDF
     * @param reason 
     */
    public void setReason(String reason) {
        this.reason = reason;
    }

    /**
     * Get AuthorName
     * @return 
     */
    public String getAuthorName() {
        return authorName;
    }

    /**
     * Get Location
     * @return 
     */
    public String getLocation() {
        return location;
    }

    /**
     * Get Reason
     * @return 
     */
    public String getReason() {
        return reason;
    }

    public PDFSignature(KeyStore keystore, String alias, char[] pin) {
        super(keystore, alias, pin);
    }
    
    /**
     * Signs the given PDF file.
     * @param inFile input PDF file
     * @param outFile output PDF file
     */
    public void signDetached(File inFile, File outFile){
        try (FileOutputStream fos = new FileOutputStream(outFile)) {
            // sign
            PDDocument doc = PDDocument.load(inFile);
            signDetached(doc, fos);
            doc.close();
            fos.close();
        } catch (Exception ex) {
            System.out.println("signDetached : "+ex);
            JOptionPane.showMessageDialog(null, "signDetached : "+ex);
        }
    }

    /**
     * Sign detached PDF
     * @param document
     * @param output
     * @throws IOException 
     */
    public void signDetached(PDDocument document, OutputStream output)
            throws IOException
    {
        int accessPermissions = SigUtils.getMDPPermission(document);
        if (accessPermissions == 1){
            throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }     

        // create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName(getAuthorName());
        signature.setLocation(getLocation());
        signature.setReason(getReason());
        // TODO extract the above details from the signing certificate? Reason as a parameter?

        // the signing date, needed for valid signature
        signature.setSignDate(Calendar.getInstance());

        // Optional: certify 
        if (accessPermissions == 0){
            SigUtils.setMDPPermission(document, signature, 2);
        }

        SignatureOptions signatureOptions = new SignatureOptions();
        // Size can vary, but should be enough for purpose.
        signatureOptions.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
        // register signature dictionary and sign interface
        document.addSignature(signature, this, signatureOptions);

        // write incremental (only for signing purpose)
        document.saveIncremental(output);
        document.close();
    }
}
