package net.sourceforge.jradiusclient.packets;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import net.sourceforge.jradiusclient.RadiusAttribute;
import net.sourceforge.jradiusclient.RadiusAttributeValues;
import net.sourceforge.jradiusclient.RadiusPacket;
import net.sourceforge.jradiusclient.attributes.ChapChallengeAttribute;
import net.sourceforge.jradiusclient.attributes.ChapPasswordAttribute;
import net.sourceforge.jradiusclient.attributes.UserNameAttribute;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;

/**
 * @author bobl
 *
 * To change the template for this generated type comment go to
 * Window>Preferences>Java>Code Generation>Code and Comments
 */
public class ChapAccessRequest extends RadiusPacket {
    //todo randomize these!!!!!!!
    private static final byte[] defaultChapChallenge;
    private static final byte defaultChapIdentifier;
    static{
        defaultChapChallenge = new byte[16];
        SecureRandom srand = new SecureRandom();
        srand.nextBytes(defaultChapChallenge);
        defaultChapIdentifier = (byte)srand.nextInt();
    }
    
    private boolean initialized = false;
    public ChapAccessRequest(final String userName, final byte[] chapEncryptedPassword, byte chapIndentifier, byte[] chapChallenge)
            throws InvalidParameterException{
        super (ACCESS_REQUEST);
        setAttribute(new UserNameAttribute(userName));
        setAttribute(new ChapPasswordAttribute(chapIndentifier,chapEncryptedPassword));
        setAttribute(new ChapChallengeAttribute(chapChallenge));
        this.initialized = true;
    }
    /**
     * 
     * @param userName
     * @param plaintextPassword
     * @throws InvalidParameterException
     */
    public ChapAccessRequest(final String userName, final String plaintextPassword )
            throws InvalidParameterException{
        this(userName,plaintextPassword.getBytes());
    }
    /**
     * 
     * @param userName
     * @param plaintextPassword
     * @throws InvalidParameterException
     */
    public ChapAccessRequest(final String userName, final byte[] plaintextPassword )
            throws InvalidParameterException{
        this(userName,chapEncrypt(defaultChapIdentifier,plaintextPassword,defaultChapChallenge),defaultChapIdentifier,defaultChapChallenge);
    }
    /**
     * 
     * @param radiusAttribute
     */
    public void validateAttribute(RadiusAttribute radiusAttribute) throws InvalidParameterException{
        if ((initialized) && (radiusAttribute.getType() == RadiusAttributeValues.USER_NAME ||
                radiusAttribute.getType() == RadiusAttributeValues.CHAP_PASSWORD ||
                radiusAttribute.getType() == RadiusAttributeValues.CHAP_CHALLENGE)){
            throw new InvalidParameterException ("Already initialized, cannot reset username, chap password or chap challenge.");
        }
    }
    private static byte[] chapEncrypt(final byte chapIdentifier, final byte[] plaintextPassword, byte[] chapChallenge){
        //pretend we are a client who is encrypting his password with a random
        //challenge from the NAS, see RFC 2865 section 2.2
        //generate next chapIdentifier
        byte[] chapPassword = plaintextPassword;// if we get an exception we will send back plaintext
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
