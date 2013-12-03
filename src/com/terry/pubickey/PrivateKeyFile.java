package com.terry.pubickey;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class PrivateKeyFile {
	PrivateKey privateKey;
	
	// constructor
	PrivateKeyFile(PrivateKey k){
		this.privateKey = k;
	}
	PrivateKeyFile(){
	}
	
	public void read(String filename) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		// read key stream from file
		File file = new File(filename);
		BufferedInputStream fin = new BufferedInputStream(
										new FileInputStream(file));
		byte[] key = new byte[(int) file.length()];
		fin.read(key);
		fin.close();
		
		// create privateKey from key stream
		PKCS8EncodedKeySpec spec =
			      new PKCS8EncodedKeySpec(key);
		KeyFactory keyfactory = KeyFactory.getInstance("RSA");
		privateKey = keyfactory.generatePrivate(spec);

	}
	public void write(String filename) throws IOException{
		byte[] key = privateKey.getEncoded();
		BufferedOutputStream fout = new BufferedOutputStream(
										new FileOutputStream(filename));
		fout.write(key);
		fout.close();
	}

}
