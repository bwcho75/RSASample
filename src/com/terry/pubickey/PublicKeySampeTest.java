package com.terry.pubickey;

import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.Test;

public class PublicKeySampeTest {

	final static String PLAINTEXT ="Hello Terry!! This is plain text for public key encryption test. 1029384756";
	@Test
	public void testKeyPair() throws Exception {
		// generate private/public key pair
		KeyGenerator gen = new KeyGenerator();
		gen.generateKey();
		PublicKey publicKey = gen.getPublicKey();
		PrivateKey privateKey = gen.getPrivateKey();
		log("PublicKey:"+publicKey);
		log("PrivateKey:"+privateKey);
		
		// encrypt plain text with public key
		MyRSAChiper c = new MyRSAChiper();
		byte[] encrypted = c.encrypt(PLAINTEXT, publicKey);
		log("Encrypted message:"+new String(encrypted));
		// decrypt it with private key
		byte[] decrypted = c.decrypt(encrypted, privateKey);
		log("Decrypted message:"+new String(decrypted));
		
		// test 2. public key file read write test
		// store the publi key to file
		PublicKeyFile publicKeyFile = new PublicKeyFile(publicKey);
		publicKeyFile.write("c:\\temp\\publickey");
		// read the publi key from file
		publicKeyFile.read("c:\\temp\\publickey");
		encrypted = c.encrypt(PLAINTEXT, publicKey);
		log("Encrypted message:"+new String(encrypted));
		// decrypt it with private key
		decrypted = c.decrypt(encrypted, privateKey);
		log("Decrypted message:"+new String(decrypted));
		

		// test 3. private key file read write test
		// store the private key to file
		PrivateKeyFile privateKeyFile = new PrivateKeyFile(privateKey);
		privateKeyFile.write("c:\\temp\\privateKey");
		// read private key from the file
		privateKeyFile.read("c:\\temp\\privateKey");
		// decrypt it with private key
		decrypted = c.decrypt(encrypted, privateKey);
		log("Decrypted message:"+new String(decrypted));	}
	
	private void log(String msg){
		System.out.println("log :"+msg);
	}


}
