/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.nerus.signdocuments.data;

import com.nerus.signdocuments.models.DatosCertificado;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.commons.ssl.PKCS8Key;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.form.PDSignatureField;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


/**
 *
 * @author msi.juliocesarortegamoreno
 */
public class SignPdf {
    
    X509Certificate certificate;
    char[] keyPassword;
    PrivateKey privateKey;

    public SignPdf( String certPath, String keyPath, String password ){
        try {
            
            this.certificate = loadCertificated( certPath );
            this.keyPassword = password.toCharArray();
            this.privateKey = loadPrivateKey( keyPath, keyPassword);
            
        } catch (Exception ex) {
            Logger.getLogger(SignPdf.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    public static X509Certificate loadCertificated(String filePath) throws FileNotFoundException, CertificateException{
        InputStream inStream = new FileInputStream( filePath );
        var cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate)cf.generateCertificate(inStream);
    }
    
    public static PrivateKey loadPrivateKey(String filePath, char[] keyPassword) throws Exception {
        FileInputStream xfile = new FileInputStream(filePath);
        PKCS8Key pkcs8 = new PKCS8Key( xfile, keyPassword);
        PrivateKey pk = pkcs8.getPrivateKey();
        return pk;
    }
       
    
    
    public void signPdf(String inputfile, String outputFile) throws FileNotFoundException, IOException, NoSuchAlgorithmException, InvalidKeyException, KeyStoreException{
        Security.addProvider(new BouncyCastleProvider());

        try ( // Load PDF document
        org.apache.pdfbox.pdmodel.PDDocument document = PDDocument.load( new FileInputStream(inputfile) )) {
            
            var datosCert = new DatosCertificado( this.certificate );
            
            
            // Create signature
            PDSignature pdSignature = new PDSignature();
            pdSignature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            pdSignature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            pdSignature.setName( datosCert.getNombre() );
            pdSignature.setReason("Reason for signing");
            
            // Load private key
            var pkSignature = Signature.getInstance("SHA256withRSA");
            pkSignature.initSign( privateKey );
            
            // Create the signature options
            SignatureOptions options = new SignatureOptions();
            options.setPreferredSignatureSize(SignatureOptions.DEFAULT_SIGNATURE_SIZE * 2);
            
            // Create the signature object
            //document.addSignature(pdSignature );
            
            // Create the SignatureInterface implementation
            SignatureInterface signatureInterface = new SignatureInterface() {
                @Override
                public byte[] sign(InputStream content) throws IOException {
                    try {
                        // Initialize the Signature object using Bouncy Castle provider
                        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
                        signature.initSign(privateKey);

                        // Read the content to sign
                        byte[] buffer = new byte[8192];
                        int n;
                        while ((n = content.read(buffer)) != -1) {
                            signature.update(buffer, 0, n);
                        }

                        // Generate the signature
                        byte[] signatureBytes = signature.sign();

                        // Return the signature
                        return signatureBytes;
                    } catch (Exception e) {
                        throw new IOException("Error signing content", e);
                    }
                }

                public Certificate[] getCertificates() {
                    List<Certificate> certificateList = new ArrayList<>();
                    certificateList.add(certificate);
                    Certificate[] certificateChain = certificateList.toArray(new Certificate[0]);
                    return certificateChain;

                }
            };
            
            // Sign the document
            //document.signSignature(pdSignature, signatureInterface, options);
            document.addSignature(pdSignature, signatureInterface, options);
            
            
            document.save( outputFile );
        
        }
    }
    
    
}
