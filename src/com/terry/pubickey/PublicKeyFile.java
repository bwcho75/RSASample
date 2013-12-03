package com.terry.pubickey;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class PublicKeyFile {
	PublicKey publicKey;
	
	// constructor
	PublicKeyFile(PublicKey k){
		this.publicKey = k;
	}
	PublicKeyFile(){
	}
	
	// write public key to file
	// reference http://docs.oracle.com/javase/tutorial/security/apisign/step4.html
	public void write(String filename) throws IOException
	{
		byte[] key = publicKey.getEncoded();
		BufferedOutputStream fout = new BufferedOutputStream(
										new FileOutputStream(filename));
		fout.write(key);
		fout.close();
	}
	
	// read public key from file
	// reference http://docs.oracle.com/javase/tutorial/security/apisign/vstep2.html
	public void read(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException
	{
		// read public key byte stream from file
		File file = new File(filename);
		BufferedInputStream fin = new BufferedInputStream(
										new FileInputStream(file));
		byte[] key = new byte[(int) file.length()];
		fin.read(key);
		fin.close();
		
		// generate publicKey from key stream
		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		publicKey = keyFactory.generatePublic(pubKeySpec);
		
		this.publicKey = publicKey;
	}
	
	public PublicKey getPublicKey(){
		return this.publicKey;
	}
}
