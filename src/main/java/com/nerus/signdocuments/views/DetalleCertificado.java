/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package com.nerus.signdocuments.views;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import com.nerus.signdocuments.models.DatosCertificado;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author msi.juliocesarortegamoreno
 */
public class DetalleCertificado extends javax.swing.JFrame {
    
    JFileChooser fileChooser;
    String certPath = "";
    DatosCertificado datosCertificado;
    

    /**
     * Creates new form CertDetails
     */
    public DetalleCertificado() {
        initComponents();
        
        fileChooser = new JFileChooser();
        fileChooser.setFileFilter( new FileNameExtensionFilter("Certificado (.cer)", "cer") );
        
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jPanel1 = new javax.swing.JPanel();
        jLabel1 = new javax.swing.JLabel();
        textfieldCert = new javax.swing.JTextField();
        jScrollPane1 = new javax.swing.JScrollPane();
        textareaDatos = new javax.swing.JTextArea();
        jLabel2 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jPanel1.setBorder(javax.swing.BorderFactory.createEtchedBorder());

        jLabel1.setText("Ruta del certificado");

        textfieldCert.setEditable(false);
        textfieldCert.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                textfieldCertMouseClicked(evt);
            }
        });
        textfieldCert.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                textfieldCertActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(6, 6, 6)
                        .addComponent(textfieldCert))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jLabel1)
                        .addGap(0, 0, Short.MAX_VALUE)))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(textfieldCert)
                .addContainerGap())
        );

        textfieldCert.getAccessibleContext().setAccessibleName("Seleccione la ruta del archivo");
        textfieldCert.getAccessibleContext().setAccessibleDescription("Seleccione la ruta del archivo");

        textareaDatos.setEditable(false);
        textareaDatos.setColumns(20);
        textareaDatos.setLineWrap(true);
        textareaDatos.setRows(5);
        textareaDatos.setWrapStyleWord(true);
        jScrollPane1.setViewportView(textareaDatos);

        jLabel2.setFont(new java.awt.Font("Helvetica Neue", 1, 24)); // NOI18N
        jLabel2.setText("DETALLES CERTIFICADO");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jLabel2)
                        .addGap(0, 620, Short.MAX_VALUE))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel2)
                .addGap(18, 18, 18)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 278, Short.MAX_VALUE)
                .addContainerGap())
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void textfieldCertActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_textfieldCertActionPerformed
        
// TODO add your handling code here:
    }//GEN-LAST:event_textfieldCertActionPerformed

    private void textfieldCertMouseClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_textfieldCertMouseClicked
        int result = fileChooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            
            this.certPath = fileChooser.getSelectedFile().getAbsolutePath();
            this.textfieldCert.setText( this.certPath);
             
            
            try {    
                loadCertificate(this.certPath);
            } catch (FileNotFoundException ex) {
                Logger.getLogger(DetalleCertificado.class.getName()).log(Level.SEVERE, null, ex);
            } catch (CertificateException ex) {
                Logger.getLogger(DetalleCertificado.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_textfieldCertMouseClicked

   

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTextArea textareaDatos;
    private javax.swing.JTextField textfieldCert;
    // End of variables declaration//GEN-END:variables

    private void loadCertificate( String certPath ) throws FileNotFoundException, CertificateException{
        InputStream inStream = new FileInputStream( certPath );
        var cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);
        // datosCertificado= new DatosCertificado( cert);
        
        List<String> certificateData = new ArrayList<>();
        certificateData.add("Subject: " + cert.getSubjectDN().toString().replace(", ", "\n\t"));
        certificateData.add("\nIssuer: " + cert.getIssuerDN().toString().replace(", ", "\n\t"));
        certificateData.add("\nValid from: " + cert.getNotBefore());
        certificateData.add("\nValid until: " + cert.getNotAfter());
        certificateData.add("\nSerial number: " + cert.getSerialNumber());
        certificateData.add("\nVersion: " + cert.getVersion());
        certificateData.add("\nSignature algorithm: " + cert.getSigAlgName());
        certificateData.add("\nPublic key: " + cert.getPublicKey());

        // Convert the certificate to PEM format and add it to the list
        String pemFormat = "-----BEGIN CERTIFICATE-----\n" +
                Base64.getEncoder().encodeToString(cert.getEncoded()) +
                "\n-----END CERTIFICATE-----";
        certificateData.add("Certificate in PEM format:\n" + pemFormat);
        
        String listText = String.join("\n", certificateData );
        this.textareaDatos.setText( listText);
        
    }
}
