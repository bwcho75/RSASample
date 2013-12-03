package com.terry.pubickey;

import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class MyRSAChiper {
	public byte[] encrypt(String plainText,PublicKey publicKey) throws GeneralSecurityException, NoSuchPaddingException{
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] originalText = plainText.getBytes();
		byte[] encryptedText = c.doFinal(originalText);
				
		return encryptedText;
	}
	public byte[] decrypt(byte[] encrypted,PrivateKey privateKey) throws NoSuchAlgorithmException, GeneralSecurityException{
		Cipher c = Cipher.getInstance("RSA");
		c.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] originalText = c.doFinal(encrypted);
		
		return originalText;
		
	}
	
	// need to add BASE64 Encoding for encrypted message and decrypt it 
}
