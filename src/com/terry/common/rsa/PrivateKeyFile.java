package com.terry.common.rsa;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class PrivateKeyFile {
        PrivateKey privateKey;
        
        // constructor
        public PrivateKeyFile(PrivateKey k){
                this.privateKey = k;
        }
        public PrivateKeyFile(){
        }
        
        // write private key to file with BASE 64 encoding format
        public void writeBase64(String filename) throws IOException{
           	byte[] key = privateKey.getEncoded();
        	String base64 = Base64Utils.encode(key);
        	BufferedWriter writer = new BufferedWriter(new FileWriter(filename));
        	writer.write(base64);
        	writer.close();
        }
        
        // read Base64 encoded private key from file
		public PrivateKey readBase64(String filename) throws IOException, GeneralSecurityException {
			// read base 64 stream from file
            File file = new File(filename);
            BufferedInputStream fin = new BufferedInputStream(new FileInputStream(file));
            byte[] buf = new byte[(int) file.length()];
            fin.read(buf);
            fin.close();
            
            // decode base64 encoded to private key byte stream
            byte[] key = Base64Utils.decode(new String(buf));
            
            // create privateKey from key stream
            PKCS8EncodedKeySpec spec =
                          new PKCS8EncodedKeySpec(key);
            KeyFactory keyfactory = KeyFactory.getInstance("RSA");
            privateKey = keyfactory.generatePrivate(spec);
			return privateKey;
		}
		public String getPrivateKeyBase64() {
			byte[] key = privateKey.getEncoded();
			return Base64Utils.encode(key);
		}

}