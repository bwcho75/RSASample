package com.terry.common.rsa.test;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Before;
import org.junit.Test;

import com.terry.common.rsa.Base64Utils;
import com.terry.common.rsa.KeyGenerator;
import com.terry.common.rsa.PrivateKeyFile;
import com.terry.common.rsa.PublicKeyFile;
import com.terry.common.rsa.RSAChiper;



public class MagicKeyTest {
	final static String PUBLICKEY_FILE="c:\\temp\\publicKey.txt";
	final static String PRIVATEKEY_FILE="c:\\temp\\privateKey.txt";
	final static String MAGICKEY_FILE="c:\\temp\\magicKey.txt";

	@Before
	public void setUp() throws GeneralSecurityException, IOException{
		// create key pair
		KeyGenerator gen = new KeyGenerator();
		gen.generateKey();
		PublicKey publicKey = gen.getPublicKey();
		PrivateKey privateKey = gen.getPrivateKey();
		PublicKeyFile publicKeyFile = new PublicKeyFile(publicKey);
		PrivateKeyFile privateKeyFile = new PrivateKeyFile(privateKey);
		log("Public Key created :"+publicKeyFile.getPublicKeyBase64());
		log("Private Key created :"+privateKeyFile.getPrivateKeyBase64());
		
		// store  keys to file
		publicKeyFile.writeBase64(PUBLICKEY_FILE);
		privateKeyFile.writeBase64(PRIVATEKEY_FILE);
	}
	
	@Test
	public void magicKeyTest() throws IOException, GeneralSecurityException{
		generateMagicKey();
		decodeMagicKey();
	}
	
	// magic key encoding step
	// magickey string --> encrypt with public key --> base64 encoding
	public void generateMagicKey() throws IOException, GeneralSecurityException{
		log("**** Magic generate ****");
		// read public key from file
		PublicKeyFile publicKeyFile = new PublicKeyFile();
		PublicKey publicKey = publicKeyFile.readBase64(PUBLICKEY_FILE);
		log("read Public Key from file:"+publicKeyFile.getPublicKeyBase64());
		
		// create MagicKey
		String plainText = "Hello RSA encryption!! ";
		RSAChiper chiper = new RSAChiper();
		byte[] encrypted = chiper.encrypt(plainText, publicKey);
		String encryptedString = Base64Utils.encode(encrypted);
		log("Original Magic Key:"+plainText);
		log("Encrypted Magic Key:"+encryptedString);
		
		// store the magic key string for decoding test
		File file = new File(MAGICKEY_FILE);
		FileWriter writer = new FileWriter(file);
		writer.write(encryptedString);
		writer.close();
		
	}
	
	// magic key decoding step
	// magickeystring --> base64 decode --> decode with privatekey
	public void decodeMagicKey() throws IOException, GeneralSecurityException{
		log("**** Magic decoding ****");
		// read private Key from file
		PrivateKeyFile privateKeyFile = new PrivateKeyFile();
		PrivateKey privateKey = privateKeyFile.readBase64(PRIVATEKEY_FILE);
		log("Private Key(Base64 format):"+privateKeyFile.getPrivateKeyBase64());
		
		// read magic key from file
		File file = new File(MAGICKEY_FILE);
		byte[] buf = new byte[(int) file.length()];
		FileInputStream in = new FileInputStream(file);
		int r=in.read(buf);
		log ("read :"+r);
		in.close();
		String encryptedString = new String(buf);
		log("encryptedString:"+encryptedString);
		
		// magicKey decode with base 64 
		byte[] key = Base64Utils.decode(encryptedString);
		// decode encoded MagicKey
		RSAChiper chiper = new RSAChiper();
		byte[] decrypted = chiper.decrypt(key, privateKey);
		log("Decrypted :"+new String(decrypted));

	}
	void log(String msg){
		System.out.println("Log : "+msg);
	}

}
