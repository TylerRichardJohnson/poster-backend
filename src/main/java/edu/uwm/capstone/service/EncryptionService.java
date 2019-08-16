package edu.uwm.capstone.service;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public class EncryptionService {

    /**
     * Returns whether the entered plain-text password matches the encrypted password
     * @param enteredPassword to compare to actual stored password
     * @param encryptedPassword the actual stored encrypted password
     * @param salt used in the encryption
     * @return true if authentication passes, otherwise false
     * @throws NoSuchAlgorithmException if attempt to use unimplemented encryption algorithm
     * @throws InvalidKeySpecException if invalid key specification
     */
    public boolean authenticate(String enteredPassword, byte[] encryptedPassword, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        byte[] encryptedEnteredPassword = getEncryption(enteredPassword, salt);
        return Arrays.equals(encryptedEnteredPassword, encryptedPassword);
    }

    /**
     * Returns the encryption of a given password using the PBKDF2 hashing algorithm
     * @param password to encrypt
     * @param salt to use for encryption
     * @return encrypted password
     * @throws NoSuchAlgorithmException if attempt to use unimplemented encryption algorithm
     * @throws InvalidKeySpecException if invalid key specification
     */
    private byte[] getEncryption(String password, byte[] salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        String algorithm = "PBKDF2WithHmacSHA1";
        int derivedKeyLength = 160;
        int iterations = 10000;
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, derivedKeyLength);
        SecretKeyFactory generator = SecretKeyFactory.getInstance(algorithm);
        return generator.generateSecret(spec).getEncoded();
    }

    /**
     * Returns a randomly generated 8 byte salt using the SHA1PRNG algorithm
     * @return the generated salt
     * @throws NoSuchAlgorithmException if attempt to use unimplemented encryption algorithm
     */
    private byte[] generateSalt() throws NoSuchAlgorithmException {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        return salt;
    }
}
