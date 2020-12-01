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
package digsig;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import egen.FileEncryption;
import egen.ShowSignature;
import customEx.CertificateVerificationException;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.List;
import org.bouncycastle.tsp.TSPException;
import validation.AddValidationInformation;

/**
 *
 * @author Eko Junaidi Salam eko.junaidi.salam@gmail.com
 */
public class PDFSigner {
    /**
     * Application Version
     */
    public static final String appVersion = "1.0.0";
    /**
     * Application Name
     */
    public static final String appName = "PDF Signer";
    
    /**
     * @param args the command line arguments
     * @throws java.io.IOException
     */
    public static void main(String[] args) throws IOException {
        System.setProperty("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.NoOpLog");
        System.out.println("Welcome to " + appName + " Version " + appVersion);
        System.out.println("Created by Eko Junaidi Salam <eko.junaidi.salam@gmail.com>");
        
        if(args.length == 1){
            if("-h".equals(args[0])) usage();
            System.exit(0);
        }
        
        if(args.length >= 2){
            Console c= System.console();
            FileEncryption fe;
            KeyStore ks;
            File ksf = new File(args[0]); // Keystore file
            File pdf = new File(args[1]); // PDF File
            File pass; // Password keystore
            File params; // Json File for alias and reason
            Boolean ltv = true;
            String passc = "";
            String alias = "";
            String reason = "";
            String tsaUrl = "https://freetsa.org/tsr";
            String tsaUsername = null;
            String tsaPassword = null;
            boolean keypass = false;
            boolean parfile = false;
            
            for(int i=0;i<args.length;i++){
                if("-verbose".equals(args[i])){
                    System.setProperty("org.apache.commons.logging.Log","org.apache.commons.logging.impl.SimpleLog");
                }
                
                if("-vv".equals(args[i])){
                    System.setProperty("org.apache.commons.logging.Log","org.apache.commons.logging.impl.Jdk14Logger");
                }
                
                if("-v".equals(args[i])){
                    ShowSignature ss = new ShowSignature();
                    try {
                        ss.showSignature(args[1]);
                    } catch (GeneralSecurityException | TSPException | CertificateVerificationException ex) {
                        System.out.println(ex.getMessage());
                    }
                    System.exit(0);
                }
                
                if("-addltv".equals(args[i])){
                    // add ocspInformation
                    if(pdf.isFile()){
                        AddValidationInformation addOcspInformation = new AddValidationInformation();
                        File inFile = new File(args[1]);
                        String oname = inFile.getName();
                        String osubstring = oname.substring(0, oname.lastIndexOf('.'));
                        addOcspInformation.validateSignature(inFile, new File(inFile.getParent(), osubstring + "_LTV.pdf"));
                    }else if(pdf.isDirectory()){
                        for(File f:pdf.listFiles()){
                            AddValidationInformation addOcspInformation = new AddValidationInformation();
                            File inFile = new File(f.getParent(), f.getName());
                            String oname = inFile.getName();
                            String osubstring = oname.substring(0, oname.lastIndexOf('.'));
                            addOcspInformation.validateSignature(inFile, new File(inFile.getParent(), osubstring + "_LTV.pdf"));
                        }
                    }
                    
                    System.exit(0);
                }
                
                if("-noltv".equals(args[i])){
                    ltv = false;
                }
                
                if("-notsa".equals(args[i])){
                    tsaUrl = "";
                }
                
                if("-k".equals(args[i])){
                    keypass = true;
                    pass = new File(args[i+1]);
                    if(pass.isFile()) passc = Files.readString(Paths.get(pass.getPath())).replaceAll("\\r\\n|\\r|\\n", "");
                }
                
                if("-p".equals(args[i])){
                    parfile = true;
                    params = new File(args[i+1]);
                    if(params.isFile()){
                        List<String> jsonPar = Files.readAllLines(Paths.get(params.getPath()));
                        StringBuilder json = new StringBuilder();

                        jsonPar.forEach((s) -> {
                            json.append(s);
                        });
                        JsonElement je = JsonParser.parseString(json.toString());
                        JsonObject jo = je.getAsJsonObject();
                        if(jo.size() >= 2){
                            alias = jo.get("alias").getAsString();
                            reason = jo.get("reason").getAsString();
                            tsaUrl = jo.get("tsaUrl").getAsString();
                            tsaUsername = jo.get("tsaUsername").getAsString();
                            tsaPassword = jo.get("tsaPassword").getAsString();
                        }
                    }
                }
            }
            
            if(!keypass){
                passc = new String(c.readPassword("Enter keystore passphrase : "));
            }
            
            if(!parfile){
                alias = c.readLine("Enter alias : ");
                reason = c.readLine("Enter reason : ");
                //tsaUrl = c.readLine("Enter tsaUrl : ");
                //tsaUsername = c.readLine("Enter tsaUsername : ");
                //tsaPassword = c.readLine("Enter tsaPassword : ");
            }
            
            if(!"".equals(passc) && ksf.isFile() && pdf.isFile()){
                fe = new FileEncryption();
                ks = fe.loadKeystore(ksf, passc);
                fe.signPDF(pdf, ks, alias, passc, reason,tsaUrl,tsaUsername,tsaPassword);
                
                if(ltv){
                    // add ocspInformation
                    AddValidationInformation addOcspInformation = new AddValidationInformation();
                    String name = pdf.getName();
                    String substring = name.substring(0, name.lastIndexOf('.'));
                    File inFile = new File(pdf.getParent(), substring + "_signed.pdf");
                    String oname = inFile.getName();
                    String osubstring = oname.substring(0, oname.lastIndexOf('.'));
                    addOcspInformation.validateSignature(inFile, new File(inFile.getParent(), osubstring + "_LTV.pdf"));
                }
            }else if(pdf.isDirectory()){
                fe = new FileEncryption();
                ks = fe.loadKeystore(ksf, passc);
                for(File f:pdf.listFiles()){
                    fe.signPDF(f, ks, alias, passc, reason,tsaUrl,tsaUsername,tsaPassword);
                    if(ltv){
                        // add ocspInformation
                        AddValidationInformation addOcspInformation = new AddValidationInformation();
                        String name = f.getName();
                        String substring = name.substring(0, name.lastIndexOf('.'));
                        File inFile = new File(f.getParent(), substring + "_signed.pdf");
                        String oname = inFile.getName();
                        String osubstring = oname.substring(0, oname.lastIndexOf('.'));
                        addOcspInformation.validateSignature(inFile, new File(inFile.getParent(), osubstring + "_LTV.pdf"));
                    }
                }
            }else{
                System.out.println("Failed to sign pdf...");
                System.exit(1);
            }
            System.exit(0);
        }
    }
    
    private static void usage()    {
        System.err.println(
            "\nusage: java -jar pdf_signer.jar " +
            "<pkcs12_keystore> <pdf_to_sign>\n" +
            "options:\n" +
            "  -verbose Enable Verbosity.\n" +
            "  -vv Enable Verbosity level 2.\n" +
            "  -v Verify DS Document.\n" +
            "  -notsa Disable TSA Stampling.\n" +
            "  -noltv Disable LTV.\n" +
            "  -addltv Add LTV to existing document.\n" +
            "  -k <file> file contains your keystore password.\n" +
            "  -p <file> json file contains your alias and reason."
        );
    }
}
