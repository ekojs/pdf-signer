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
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.util.List;

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
            String passc = "";
            String alias = "";
            String reason = "";
            boolean keypass = false;
            boolean parfile = false;
            
            for(int i=0;i<args.length;i++){
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
                        if(jo.size() == 2){
                            alias = jo.get("alias").getAsString();
                            reason = jo.get("reason").getAsString();
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
            }
            
            if(!"".equals(passc) && ksf.isFile() && pdf.isFile()){
                fe = new FileEncryption();
                ks = fe.loadKeystore(ksf, passc);
                fe.signPDF(pdf, ks, alias, passc, reason);
            }else if(pdf.isDirectory()){
                fe = new FileEncryption();
                ks = fe.loadKeystore(ksf, passc);
                for(File f:pdf.listFiles()){
                    fe.signPDF(f, ks, alias, passc, reason);
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
            "  -k <file> file contains your keystore password.\n" +
            "  -p <file> json file contains your alias and reason."
        );
    }
}
