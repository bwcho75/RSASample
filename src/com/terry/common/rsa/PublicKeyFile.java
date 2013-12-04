package com.terry.common.rsa;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyFile {
        PublicKey publicKey;
        
        // constructor
        public PublicKeyFile(PublicKey k){
                this.publicKey = k;
        }
        public PublicKeyFile(){
        }
        
        // write public key to file with base64 encryption
        // reference http://docs.oracle.com/javase/tutorial/security/apisign/step4.html
       
        public void writeBase64(String filename) throws IOException
        {
        	byte[] key = publicKey.getEncoded();
        	String base64 = Base64Utils.encode(key);
        	BufferedWriter writer = new BufferedWriter(new FileWriter(filename));
        	writer.write(base64);
        	writer.close();
        }
        
        // read base64 encoded public key from file
        // reference http://docs.oracle.com/javase/tutorial/security/apisign/vstep2.html
        
        public PublicKey readBase64(String filename) throws IOException, GeneralSecurityException{
        	// read public key byte stream from file
            File file = new File(filename);
            BufferedInputStream fin = new BufferedInputStream(new FileInputStream(file));
            byte[] buf = new byte[(int) file.length()];
            fin.read(buf);
            fin.close();
            
            // decode binary base64 stream to byte stream
            byte[] key = Base64Utils.decode(new String(buf));
            // generate publicKey from key stream
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            publicKey = keyFactory.generatePublic(pubKeySpec);
            
            this.publicKey = publicKey;
            
            return publicKey;
            
        }
        
        // return publickey with base64 encoding format
        public String getPublicKeyBase64(){
        	byte[] key = publicKey.getEncoded();
        	String base64 = Base64Utils.encode(key);
        	return base64;
        }
        
        public PublicKey getPublicKey(){
                return this.publicKey;
        }
}