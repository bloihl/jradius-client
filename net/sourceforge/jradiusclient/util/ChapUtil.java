package net.sourceforge.jradiusclient.util;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Released under the LGPL<BR>
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class ChapUtil {   
    private SecureRandom srand = null;
    /**
     * 
     *
     */
    public ChapUtil(){
        this.srand = new SecureRandom();
    }
    /**
     * 
     * @return
     */
    public byte getNextChapIdentifier(){
        synchronized (this.srand){
            return (byte)this.srand.nextInt(255);
        }
    }
    /**
     * 
     * @param size
     * @return
     */
    public byte[] getNextChapChallenge(final int size){
        byte[] challenge = new byte[size];
        synchronized (this.srand){
            this.srand.nextBytes(challenge);
        }
        return challenge;
    }
    /**
     * This method performs the CHAP encryption according to RFC 2865 section 2.2 for use with Radius Servers using
     * MD5 as the one way hashing algorithm
     * @param chapIdentifier a byte to help correlate unique challenges/responses
     * @param plaintextPassword exactly what it says. 
     * @param chapChallenge the bytes to encode the plaintext password with
     * @return the encrypted password as a byte array (16 bytes to be exact as a result of the MD5 process)
     */
    public static final byte[] chapEncrypt(final byte chapIdentifier, final byte[] plaintextPassword, byte[] chapChallenge){
        //pretend we are a client who is encrypting his password with a random
        //challenge from the NAS, see RFC 2865 section 2.2
        //generate next chapIdentifier
        byte[] chapPassword = plaintextPassword;// if we get an error we will send back plaintext
        try{
            MessageDigest md5MessageDigest = MessageDigest.getInstance("MD5");
            md5MessageDigest.reset();
            md5MessageDigest.update(chapIdentifier);
            md5MessageDigest.update(plaintextPassword);
            chapPassword = md5MessageDigest.digest(chapChallenge);
        }catch(NoSuchAlgorithmException nsaex) {
            throw new RuntimeException("Could not access MD5 algorithm, fatal error", nsaex);
        }
        return chapPassword;
    }

}
