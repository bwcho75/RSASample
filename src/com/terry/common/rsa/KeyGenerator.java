package com.terry.common.rsa;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

// generate Public/Private Key pair
public class KeyGenerator {
        PublicKey publicKey;
        PrivateKey privateKey;
        final static int KEYSIZE=1024;
        
        public void generateKey() throws NoSuchAlgorithmException{
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(KEYSIZE);
                KeyPair keyPair = generator.generateKeyPair();
                publicKey = keyPair.getPublic();
                privateKey = keyPair.getPrivate();
        }
        public PublicKey getPublicKey(){ return publicKey;}
        public PrivateKey getPrivateKey() { return privateKey;}
}