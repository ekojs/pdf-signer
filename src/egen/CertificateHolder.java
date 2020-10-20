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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;

/**
 *
 * @author Eko Junaidi Salam eko.junaidi.salam@gmail.com
 */
public class CertificateHolder {
    private static CertificateHolder init = null;
    
    private String Country;
    private String State;
    private String Location;
    private String Organization;
    private String Unit;
    private String Name;
    
    /**
     * Instantiate singleton for Certificate Holder
     * @return CertificateHolder
     */
    public static CertificateHolder getInstance(){
        if(init == null)
            init =  new CertificateHolder();
        return init;
    }

    /**
     * Set Certificate X509
     * @param cert 
     */
    public void setCert(X509Certificate cert) {
        try {
            X500Name dn = new JcaX509CertificateHolder(cert).getSubject();
            RDN cn = dn.getRDNs(BCStyle.CN)[0];
            RDN unit = dn.getRDNs(BCStyle.OU)[0];
            RDN org = dn.getRDNs(BCStyle.O)[0];
            RDN loc = dn.getRDNs(BCStyle.L)[0];
            RDN state = dn.getRDNs(BCStyle.ST)[0];
            RDN country = dn.getRDNs(BCStyle.C)[0];
            
            setName(IETFUtils.valueToString(cn.getFirst().getValue()));
            setUnit(IETFUtils.valueToString(unit.getFirst().getValue()));
            setOrganization(IETFUtils.valueToString(org.getFirst().getValue()));
            setLocation(IETFUtils.valueToString(loc.getFirst().getValue()));
            setState(IETFUtils.valueToString(state.getFirst().getValue()));
            setCountry(IETFUtils.valueToString(country.getFirst().getValue()));
        } catch (CertificateEncodingException ex) {
            System.out.println(getClass().getName()+" CertificateHolder : "+ex);
        }
    }

    /**
     * Get Country ID
     * @return 
     */
    public String getCountry() {
        return Country;
    }

    private void setCountry(String Country) {
        this.Country = Country;
    }

    /**
     * Get State
     * @return 
     */
    public String getState() {
        return State;
    }

    private void setState(String State) {
        this.State = State;
    }

    /**
     * Get Location
     * @return 
     */
    public String getLocation() {
        return Location;
    }

    private void setLocation(String Location) {
        this.Location = Location;
    }

    /**
     * Get Organization Name
     * @return 
     */
    public String getOrganization() {
        return Organization;
    }

    private void setOrganization(String Organization) {
        this.Organization = Organization;
    }

    /**
     * Get Organization Unit
     * @return 
     */
    public String getUnit() {
        return Unit;
    }

    private void setUnit(String Unit) {
        this.Unit = Unit;
    }

    /**
     * Get Common Name
     * @return 
     */
    public String getName() {
        return Name;
    }

    private void setName(String Name) {
        this.Name = Name;
    }
}
