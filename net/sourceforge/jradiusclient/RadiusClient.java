package net.sourceforge.jradiusclient;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.Random;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import net.sourceforge.jradiusclient.exception.RadiusException;


/**
 * Released under the LGPL<BR>
 *
 * This class provides basic functionality required to implement a NAS as
 * defined by the RADIUS protocol as specified in RFC 2865 and RFC 2866. 
 * This implementation is stateless and not thread safe, i.e. since the 
 * user name could be changed by the current thread or any other thread,
 * it is difficult to ensure that the responseAttributes correlate to the 
 * request we think we are dealing with. It is up to the user of this class 
 * to ensure these things at this point. A future release may change this class
 * to a stateful, threadsafe object, but it works for now. Users of this class 
 * must also manage building their own request attributes and submitting them with 
 * their call to authenticate. For example a programmer using this library, wanting
 * to do chap authentication needs to generate the random challenge, send it to
 *  the user, who generates the MD5 of 
 * <UL><LI>a self generated CHAP identifier (a byte)</LI> 
 * <LI>their password</LI> 
 * <LI>and the CHAP challenge.</LI></UL>(see RFC 2865 section 2.2) The user 
 * software returns the CHAP Identifier and the MD5 result and the programmer using RadiusClient
 * sets that as the CHAP Password. The programmer also sets the CHAP-Challenge attribute and
 * sends that to the Radius Server for authentication.
 *
 * <BR>Special Thanks to the original creator of the "RadiusClient"
 * <a href="http://augiesoft.com/java/radius/">August Mueller </a>
 * http://augiesoft.com/java/radius/ and to
 * <a href="http://sourceforge.net/projects/jradius-client">Aziz Abouchi</a>
 * for laying the groundwork for the development of this class.
 *
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.30 $
 */
public class RadiusClient
{
    private static byte [] NAS_ID;
    private static byte [] NAS_IP;
    private static final int AUTH_LOOP_COUNT = 3;
    private static final int ACCT_LOOP_COUNT = 3;
    private static final int DEFAULT_AUTH_PORT = 1812;
    private static final int DEFAULT_ACCT_PORT = 1813;
    private static final int DEFAULT_SOCKET_TIMEOUT = 6000;
    private String sharedSecret = "";
    private InetAddress hostname = null;
    private int authenticationPort = DEFAULT_AUTH_PORT;
    private int accountingPort = DEFAULT_ACCT_PORT;
    private DatagramSocket socket = null;
    private int socketTimeout = DEFAULT_SOCKET_TIMEOUT;
    private MessageDigest md5MessageDigest;
    /*
     * Static Initializer
     */
    static {
        try{
            InetAddress localHost = InetAddress.getLocalHost();
            NAS_ID = (localHost.getHostName()).getBytes();
            NAS_IP = (localHost.getHostAddress()).getBytes();
        }catch (UnknownHostException uhex){
            //If this happens the host has no IP address, what can we do???
            //everything will be fouled up anyway!!
            throw new RuntimeException(uhex.getMessage());
        }
    }
    /**
     * Constructor - uses the default port 1812 for authentication and 1813 for accounting
     * @param hostname java.lang.String
     * @param sharedSecret java.lang.String
     * @exception java.net.SocketException If we could not create the necessary socket
     * @exception java.security.NoSuchAlgorithmException If we could not get an
     *                              instance of the MD5 algorithm.
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If an invalid hostname
     *                              (null or empty string), an invalid port
     *                              (port < 0 or port > 65536) or an invalid
     *                              shared secret (null, shared secret can be
     *                              empty string) is passed in.
     */
    public RadiusClient(String hostname, String sharedSecret)
    throws RadiusException, InvalidParameterException{
        this(hostname, DEFAULT_AUTH_PORT, DEFAULT_ACCT_PORT, sharedSecret, DEFAULT_SOCKET_TIMEOUT);
    }
    /**
     * Constructor allows the user to specify an alternate port for the radius server
     * @param hostname java.lang.String
     * @param authPort int the port to use for authentication requests
     * @param acctPort int the port to use for accounting requests
     * @param sharedSecret java.lang.String
     * @exception java.net.SocketException If we could not create the necessary socket
     * @exception java.security.NoSuchAlgorithmException If we could not get an
     *                              instance of the MD5 algorithm.
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If an invalid hostname
     *                              (null or empty string), an invalid
     *                              port ( port < 0 or port > 65536)
     *                              or an invalid shared secret (null, shared
     *                              secret can be empty string) is passed in.
     */
    public RadiusClient(String hostname, int authPort, int acctPort, String sharedSecret)
    throws RadiusException, InvalidParameterException{
        this(hostname, authPort, acctPort, sharedSecret, DEFAULT_SOCKET_TIMEOUT);
    }
    /**
     * Constructor allows the user to specify an alternate port for the radius server
     * @param hostname java.lang.String
     * @param authPort int the port to use for authentication requests
     * @param acctPort int the port to use for accounting requests
     * @param sharedSecret java.lang.String
     * @param timeout int the timeout to use when waiting for return packets can't be neg and shouldn't be zero
     * @exception net.sourceforge.jradiusclient.exception.RadiusException If we could not create the necessary socket,
     * If we could not get an instance of the MD5 algorithm, or the hostname did not pass validation
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If an invalid hostname
     *                              (null or empty string), an invalid
     *                              port ( port < 0 or port > 65536)
     *                              or an invalid shared secret (null, shared
     *                              secret can be empty string) is passed in.
     */
    public RadiusClient(String hostname, int authPort, int acctPort, String sharedSecret, int sockTimeout)
    throws RadiusException, InvalidParameterException{
        this.setHostname(hostname);
        this.setSharedSecret(sharedSecret);
        //set up the socket for this client
        try{
            this.socket = new DatagramSocket();
        }catch(SocketException sex){
            throw new RadiusException(sex.getMessage());
        }
        this.setTimeout(sockTimeout);
        //set up the md5 engine
        try{
        this.md5MessageDigest = MessageDigest.getInstance("MD5");
        }catch(NoSuchAlgorithmException nsaex){
            throw new RadiusException(nsaex.getMessage());
        }
        this.setAuthPort(authPort);
        this.setAcctPort(acctPort);
    }
    /**
     * This method performs the job of authenticating the specified user against
     * the radius server.
     * @param userPass java.lang.String
     * @return int Will be one of three possible values RadiusClient.ACCESS_ACCEPT,
     *      RadiusClient.ACCESS_REJECT or RadiusClient.ACCESS_CHALLENGE
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     * @exception net.sourceforge.jradiusclient.exception.RadiusException
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException
     */
    public RadiusPacket authenticate(RadiusPacket accessRequest)
    throws RadiusException, InvalidParameterException {
        return this.authenticate(accessRequest, RadiusClient.AUTH_LOOP_COUNT);
    }
    /**
     * This method performs the job of authenticating the specified user against
     * the radius server.
     * @param userPass java.lang.String plaintext userPass to be encrypted using PAP algorithm
     * @param requestAttributes ByteArrayOutputStream
     * @param int retries must be zero or greater if it is zero default value of 3 will be used
     * @return int Will be one of three possible values RadiusClient.ACCESS_ACCEPT,
     *      RadiusClient.ACCESS_REJECT or RadiusClient.ACCESS_CHALLENGE
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     * @exception net.sourceforge.jradiusclient.exception.RadiusException
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException
     */
    public RadiusPacket authenticate(RadiusPacket accessRequest, int retries)
    throws RadiusException, InvalidParameterException {
        if(null == accessRequest){
            throw new InvalidParameterException("accessRequest parameter cannot be null");
        }
        if(retries < 0){
            throw new InvalidParameterException("retries must be zero or greater!");
        }else if (retries == 0){
            retries = RadiusClient.AUTH_LOOP_COUNT;
        }
        byte code = accessRequest.getPacketType();
        if(code != RadiusPacket.ACCESS_REQUEST){  //1 byte: code
            throw new InvalidParameterException("Invalid packet type submitted to authenticate");
        }
        byte identifier = accessRequest.getPacketIdentifier();  //1 byte: Identifier can be anything, so should not be constant

        //16 bytes: Request Authenticator
        byte [] requestAuthenticator = this.makeRFC2865RequestAuthenticator();

        // USER_NAME should be set as an attribute already
        //USER_PASSWORD may or may not be set
        try{
            byte [] userPass = accessRequest.getAttribute(RadiusAttributeValues.USER_PASSWORD).getValue();
            if(userPass.length > 0){//otherwise we don't add it to the Attributes
                byte [] encryptedPass = this.encryptPapPassword(userPass, requestAuthenticator);
                //(encryptPass gives ArrayIndexOutOfBoundsException if password is of zero length)
                accessRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.USER_PASSWORD, encryptedPass));
            }
        }catch(RadiusException rex){
            //only thrown if there isn't a matching attribute justifiable to ignore
            //user needs to make sure he builds RadiusPackets correctly
        }
        // Set the NAS-Identifier
        accessRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.NAS_IDENTIFIER, RadiusClient.NAS_ID));
        // Length of Packet is computed as follows, 20 bytes (corresponding to
        // length of code + Identifier + Length + Request Authenticator) +
        // each attribute has a length computed as follows: 1 byte for the type +
        // 1 byte for the length of the attribute + length of attribute bytes
        byte[] requestAttributes = accessRequest.getAttributeBytes();
        short length = (short) (RadiusPacket.RADIUS_HEADER_LENGTH + requestAttributes.length );

        DatagramPacket packet =
            this.composeRadiusPacket(this.getAuthPort(), code, identifier, length, requestAuthenticator, requestAttributes);
        // now send the request and receive the response
        RadiusPacket responsePacket = null;
        if ((packet = this.sendReceivePacket(packet, retries)) != null){
            responsePacket = this.checkRadiusPacket(packet,identifier, requestAuthenticator);
        }else{
            throw new RadiusException("null returned from sendReceivePacket");
        }
        return responsePacket;//won't ever return null
    }
    /**
     *
     * @param java.lang.String sessionID the session identifier we are accounting
     *      against for this user
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean startAccounting(String sessionID) throws IOException, UnknownHostException{
        return this.startAccounting(sessionID, null);
    }
    /**
     *
     * @param java.lang.String sessionID the session identifier we are accounting
     *      against for this user
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean updateAccounting(String sessionID) throws IOException, UnknownHostException{
        return this.updateAccounting(sessionID, null);
    }
    /**
     *
     * @param java.lang.String sessionID the session identifier we are accounting
     *      against for this user
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean stopAccounting(String sessionID) throws IOException, UnknownHostException{
        return this.stopAccounting(sessionID, null);
    }
    /**
     *
     * @param java.lang.String sessionID the session identifier we are accounting
     *      against for this user
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean enableAccounting(String sessionID) throws IOException, UnknownHostException{
        return this.enableAccounting(sessionID, null);
    }
    /**
     *
     * @param java.lang.String sessionID the session identifier we are accounting
     *      against for this user
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean disableAccounting(String sessionID) throws IOException, UnknownHostException{
        return this.disableAccounting(sessionID, null);
    }
    /**
     *
     * @param sessionID the session identifier we are accounting
     *      against for this user
     * @param requestAttributes Any additional attributes you might require to add to the accounting packet. (J.B. 25/08/2003)
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean startAccounting(String sessionID, ByteArrayOutputStream requestAttributes)
            throws IOException, UnknownHostException
    {
        byte[] service = new byte[]{0, 0, 0, 1};
        try{
            return this.account(service, sessionID, requestAttributes);
        }catch (RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
    }

    /**
     *
     * @param sessionID the session identifier we are accounting
     *      against for this user
     * @param requestAttributes Any additional attributes you might require to add to the accounting packet. (J.B. 25/08/2003)
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean updateAccounting(String sessionID, ByteArrayOutputStream requestAttributes)
            throws IOException, UnknownHostException
    {
        byte[] service = new byte[]{0, 0, 0, 3};
        try{
            return this.account(service, sessionID, requestAttributes);
        }catch (RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
    }

    /**
     *
     * @param sessionID the session identifier we are accounting
     *      against for this user
     * @param requestAttributes Any additional attributes you might require to add to the accounting packet. (J.B. 25/08/2003)
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean stopAccounting(String sessionID, ByteArrayOutputStream requestAttributes)
            throws IOException, UnknownHostException
    {
        byte[] service = new byte[]{0, 0, 0, 2};
        try{
            return this.account(service, sessionID, requestAttributes);
        }catch (RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
    }

    /**
     *
     * @param sessionID the session identifier we are accounting
     *      against for this user
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean enableAccounting(String sessionID, ByteArrayOutputStream requestAttributes)
            throws IOException, UnknownHostException
    {
        byte[] service = new byte[]{0, 0, 0, 7};
        try{
            return this.account(service, sessionID, requestAttributes);
        }catch (RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
    }

    /**
     *
     * @param sessionID the session identifier we are accounting
     *      against for this user
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     */
    public boolean disableAccounting(String sessionID, ByteArrayOutputStream requestAttributes)
            throws IOException, UnknownHostException
    {
        byte[] service = new byte[]{0, 0, 0, 8};
        try{
            return this.account(service, sessionID, requestAttributes);
        }catch (RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
    }
    /**
     * This method performs the job of sending accounting information for the
     * current user to the radius accounting server.
     * @param byte[] service the type of accounting we are going to do MUST BE 4 BYTES LONG
     * @param java.lang.String sessionID the session identifier we are accounting
     *      against for this user
     * @return boolean Whether or not this accounting request was successfull
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     * @exception net.sourceforge.jradiusclient.exception.radius.RadiusException
     */
    private boolean account(byte[] service, String sessionId) throws IOException,
                                        UnknownHostException, RadiusException{
        return this.account(service, sessionId, null);
    }
    /**
      * This method performs the job of sending accounting information for the
      * current user to the radius accounting server.
      * @param service the type of accounting we are going to do MUST BE 4 BYTES LONG
      * @param sessionId the session identifier we are accounting
      *      against for this user
      * @param reqAttributes Any additional request attributes to add to the accounting packet. (J.B. 25/08/2003)
      * @return boolean Whether or not this accounting request was successfull
      * @exception java.io.IOException
      * @exception java.net.UnknownHostException
      * @exception net.sourceforge.jradiusclient.exception.RadiusException
      */
    private boolean account(byte[] service, String sessionId, ByteArrayOutputStream reqAttributes)
            throws IOException,UnknownHostException, RadiusException{
                
        byte code = RadiusPacket.ACCOUNTING_REQUEST;
        byte identifier = 0;//RadiusClient.getNextIdentifier();
        if (service.length != 4){
            throw new RadiusException("The service byte array must have a length of 4");
        }

        if ((sessionId == null) || (sessionId == "")){
            //sessionId = "session" + this.userName;
        }
        
        ByteArrayOutputStream requestAttributes = null;
        if (reqAttributes != null){
            requestAttributes = reqAttributes;
        }else{
            requestAttributes = new ByteArrayOutputStream();
        }
        
//        this.setAttribute(RadiusAttributeValues.USER_NAME, this.userName.getBytes(), requestAttributes);
//        this.setAttribute(RadiusAttributeValues.NAS_IDENTIFIER, RadiusClient.NAS_ID, requestAttributes);
//        this.setAttribute(RadiusAttributeValues.ACCT_STATUS_TYPE, service, requestAttributes); // Acct-Status-Type
//        this.setAttribute(RadiusAttributeValues.ACCT_SESSION_ID, sessionId.getBytes(), requestAttributes);
//        this.setAttribute(RadiusAttributeValues.SERVICE_TYPE, service, requestAttributes);
        
        // Length of Packet is computed as follows, 20 bytes (corresponding to
        // length of code + Identifier + Length + Request Authenticator) +
        // each attribute has a length computed as follows: 1 byte for the type +
        // 1 byte for the length of the attribute + length of attribute bytes
        short length = (short) (RadiusPacket.RADIUS_HEADER_LENGTH + requestAttributes.size());
        byte[] requestAuthenticator =
            this.makeRFC2866RequestAuthenticator(code, identifier, length, requestAttributes.toByteArray());
        
        DatagramPacket packet =
            this.composeRadiusPacket(this.getAcctPort(), code, identifier, length, requestAuthenticator, requestAttributes.toByteArray());
        //send the request / recieve the response
        if ((packet = this.sendReceivePacket(packet, RadiusClient.ACCT_LOOP_COUNT)) != null) {
            if (RadiusPacket.ACCOUNTING_RESPONSE == this.checkRadiusPacket(packet, identifier, requestAuthenticator).getPacketType()) {
                return true;
            }
        }
        //else we didn't get back a response which indicates failure to
        //communicate successfully with the RADIUS Accounting
        return false;
    }
    /**
     * This method encrypts the plaintext user password according to RFC 2865
     * @param userPass java.lang.String the password to encrypt
     * @param requestAuthenticator byte[] the requestAuthenicator to use in the encryption
     * @return byte[] the byte array containing the encrypted password
     */
    private byte [] encryptPapPassword(final byte[] userPass, final byte [] requestAuthenticator) {
        // encrypt the password.
        byte[] userPassBytes = null;
        //the password must be a multiple of 16 bytes and less than or equal
        //to 128 bytes. If it isn't a multiple of 16 bytes fill it out with zeroes
        //to make it a multiple of 16 bytes. If it is greater than 128 bytes
        //truncate it at 128

        if (userPass.length > 128){
            userPassBytes = new byte[128];
            System.arraycopy(userPass,0,userPassBytes,0,128);
        }else {
            userPassBytes = userPass;
        }
        // declare the byte array to hold the final product
        byte[] encryptedPass = null;

        if (userPassBytes.length < 128) {
            if (userPassBytes.length % 16 == 0) {
                // It is already a multiple of 16 bytes
                encryptedPass = new byte[userPassBytes.length];
            } else {
                // Make it a multiple of 16 bytes
                encryptedPass = new byte[((userPassBytes.length / 16) * 16) + 16];
            }
        } else {
            // the encrypted password must be between 16 and 128 bytes
            encryptedPass = new byte[128];
        }

        // copy the userPass into the encrypted pass and then fill it out with zeroes
        System.arraycopy(userPassBytes, 0, encryptedPass, 0, userPassBytes.length);
        for(int i = userPassBytes.length; i < encryptedPass.length; i++) {
            encryptedPass[i] = 0;  //fill it out with zeroes
        }

        this.md5MessageDigest.reset();
        // add the shared secret
        this.md5MessageDigest.update(this.sharedSecret.getBytes());
        // add the  Request Authenticator.
        this.md5MessageDigest.update(requestAuthenticator);
        // get the md5 hash( b1 = MD5(S + RA) ).
        byte bn[] = this.md5MessageDigest.digest();

        for (int i = 0; i < 16; i++){
            // perform the XOR as specified by RFC 2865.
            encryptedPass[i] = (byte)(bn[i] ^ encryptedPass[i]);
        }

        if (encryptedPass.length > 16){
            for (int i = 16; i < encryptedPass.length; i+=16){
                this.md5MessageDigest.reset();
                // add the shared secret
                this.md5MessageDigest.update(this.sharedSecret.getBytes());
                //add the previous(encrypted) 16 bytes of the user password
                this.md5MessageDigest.update(encryptedPass, i - 16, 16);
                // get the md5 hash( bn = MD5(S + c(i-1)) ).
                bn = this.md5MessageDigest.digest();
                for (int j = 0; j < 16; j++) {
                    // perform the XOR as specified by RFC 2865.
                    encryptedPass[i+j] = (byte)(bn[j] ^ encryptedPass[i+j]);
                }
            }
        }
        return encryptedPass;
    }

    /**
     * This method builds a Request Authenticator for use in outgoing RADIUS
     * Access-Request packets as specified in RFC 2865.
     * @return byte[]
     */
    private byte[] makeRFC2865RequestAuthenticator() {
        byte [] requestAuthenticator = new byte [16];

        Random r = new Random();

        for (int i = 0; i < 16; i++)
        {
            requestAuthenticator[i] = (byte) r.nextInt();
        }
        this.md5MessageDigest.reset();
        this.md5MessageDigest.update(this.sharedSecret.getBytes());
        this.md5MessageDigest.update(requestAuthenticator);

        return this.md5MessageDigest.digest();
    }
    /**
     * This method builds a Response Authenticator for use in validating
     * responses from the RADIUS Authentication process as specified in RFC 2865.
     * The byte array returned should match exactly the response authenticator
     * recieved in the response packet.
     * @param code byte
     * @param identifier byte
     * @param length short
     * @param requestAuthenticator byte[]
     * @param responseAttributeBytes byte[]
     * @return byte[]
     */
    private byte[] makeRFC2865ResponseAuthenticator(byte code,
                                                byte identifier,
                                                short length,
                                                byte [] requestAuthenticator,
                                                byte[] responseAttributeBytes) {
        this.md5MessageDigest.reset();

        this.md5MessageDigest.update((byte)code);
        this.md5MessageDigest.update((byte)identifier);
        this.md5MessageDigest.update((byte)(length >> 8));
        this.md5MessageDigest.update((byte)(length & 0xff));
        this.md5MessageDigest.update(requestAuthenticator, 0, requestAuthenticator.length);
        this.md5MessageDigest.update(responseAttributeBytes, 0, responseAttributeBytes.length);
        this.md5MessageDigest.update(this.sharedSecret.getBytes());

        return this.md5MessageDigest.digest();
    }
    /**
     * This method builds a Request Authenticator for use in RADIUS Accounting
     * packets as specified in RFC 2866.
     * @param code byte
     * @param identifier byte
     * @param length short
     * @param requestAttributes byte[]
     * @return byte[]
     */
    private byte[] makeRFC2866RequestAuthenticator(byte code,
                                                    byte identifier,
                                                    short length,
                                                    byte[] requestAttributes) {
        byte [] requestAuthenticator = new byte [16];

        for (int i = 0; i < 16; i++) {
                requestAuthenticator[i] = 0;
        }
        this.md5MessageDigest.reset();

        this.md5MessageDigest.update((byte)code);
        this.md5MessageDigest.update((byte)identifier);
        this.md5MessageDigest.update((byte)(length >> 8));
        this.md5MessageDigest.update((byte)(length & 0xff));
        this.md5MessageDigest.update(requestAuthenticator, 0, requestAuthenticator.length);
        this.md5MessageDigest.update(requestAttributes, 0, requestAttributes.length);
        this.md5MessageDigest.update(this.sharedSecret.getBytes());

        return this.md5MessageDigest.digest();
    }
    /**
     * This method returns the current Host Name to be used for RADIUS
     * authentication or accounting
     * @return java.lang.String The name of the host the radius server is
     *                          running on. Can be either the name or the
     *                          dotted-quad IP address
     */
    public String getHostname() {
        return this.hostname.getHostName();
    }
    /**
     * This method sets the Host Name to be used for RADIUS
     * authentication or accounting
     * @param hostname java.lang.String The name of the host the RADIUS server is
     *                          running on. Can be either the name or the
     *                          dotted-quad IP address
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If the hostname is null,
     *                          empty or all blanks
     */
    private void setHostname(String hostname) throws InvalidParameterException{
        if (hostname == null){
            throw new InvalidParameterException("Hostname can not be null!");
        }else if (hostname.trim().equals("")){
            throw new InvalidParameterException("Hostname can not be empty or all blanks!");
        }else{
            try{
                this.hostname = InetAddress.getByName(hostname);
            }catch(java.net.UnknownHostException uhex){
                throw new InvalidParameterException("Hostname failed InetAddress.getByName() validation!");
            }
        }
    }
    /**
     * This method returns the current port to be used for authentication
     * @return int
     */
    public int getAuthPort(){
        return this.authenticationPort;
    }
    /**
     * This method sets the port to be used for authentication
     * @param port int
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If the port is less
     *                          than 0 or greater than 65535
     */
    private void setAuthPort(int port) throws InvalidParameterException
    {
        if ((port > 0) && (port < 65536)){
            this.authenticationPort = port;
        }else{
            throw new InvalidParameterException("Port value out of range!");
        }
    }
    /**
     * This method returns the current port to be used for accounting
     * @return int
     */
    public int getAcctPort(){
        return this.accountingPort;
    }
    /**
     * This method sets the port to be used for accounting
     * @param port int
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If the port is less
     *                          than 0 or greater than 65535
     */
    private void setAcctPort(int port) throws InvalidParameterException
    {
        if ((port > 0) && (port < 65536)){
            this.accountingPort = port;
        }else{
            throw new InvalidParameterException("Port value out of range!");
        }
    }
    /**
     * This method returns the current secret value that the Radius Client
     * shares with the RADIUS Server.
     * @return java.lang.String
     */
    public String getSharedSecret() {
        return this.sharedSecret;
    }
    /**
     * This method sets the secret value that the Radius Client shares with the
     * RADIUS Server.
     * @param sharedSecret java.lang.String
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If the shared secret is null,
     *                          or the empty string
     */
    private void setSharedSecret(String sharedSecret) throws InvalidParameterException {
        if (sharedSecret == null){
            throw new InvalidParameterException("Shared secret can not be null!");
        }else if (sharedSecret.equals("")){//we don't trim() the string here because the rfc (RFC 2865)
                                            //states the shared secret can't be empty string
                                            // but doesn't exclude an all blank string
            throw new InvalidParameterException("Shared secret can not be an empty string!");
        }else{//everything is a-ok
            this.sharedSecret = sharedSecret;
        }
    }
    /**
     * This method returns the current timeout period on a recieve of a response
     * from the RADIUS Server.
     * @return int
     */
    public int getTimeout() {
        return this.socketTimeout;
    }
    /**
     * This method sets the timeout period on a recieve of a response from the
     * RADIUS Server.
     * @param socket_timeout int a positive timeout value
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If the timeout value is
     *                          less than 0. a 0 value for timeout means that the
     *                          request will block until a response is recieved,
     *                          which is not recommended due to the nature of RADIUS
     *                          (i.e. RADIUS server may be silently dropping your
     *                          packets and never sending a response)
     */
    private void setTimeout(int socket_timeout) throws InvalidParameterException {
        if (socket_timeout < 0){
            throw new InvalidParameterException("A negative timeout value is not allowed!");
        }else{//everything is a-ok
            this.socketTimeout = socket_timeout;
	    try{
		if(null == this.socket) {//prevent NPE
		    this.socket = new DatagramSocket();
		}
		this.socket.setSoTimeout(this.socketTimeout);
	    }catch(SocketException sex){}
        }
    }
    /**
     * @param packet java.net.DatagramPacket
     * @param requestIdentifier byte
     * @param requestAuthenticator byte[]
     * @return int the code value from the radius response packet
     * @exception net.sourceforge.jradiusclient.exception.RadiusException
     * @exception java.io.IOException
     */
    private RadiusPacket checkRadiusPacket(DatagramPacket packet,
                                        byte requestIdentifier,
                                        byte[] requestAuthenticator)
    throws RadiusException{
        ByteArrayInputStream bais = new ByteArrayInputStream(packet.getData());
        DataInputStream input = new DataInputStream(bais);
        try{
            int returnCode = -1;
            int packetLength = packet.getLength();
            byte code = input.readByte();
            returnCode = code & 0xff;
            //now check the identifiers to see if they match
            byte identifierByte = input.readByte();
            //int identifier = identifierByte & 0xff;//don't need this
            if (identifierByte != requestIdentifier){
                //wrong packet asshole!
                throw new RadiusException("The RADIUS Server returned the wrong Identifier.");
            }
            //read the length
            short length = (short)((int)input.readShort() & 0xffff);
            //now check the response authenticator to validate the packet
            byte [] responseAuthenticator = new byte[16];
            input.readFully(responseAuthenticator);
            //get the attributes as a byte[]
            byte[] responseAttributeBytes = new byte[length - RadiusPacket.RADIUS_HEADER_LENGTH];
            input.readFully(responseAttributeBytes);
            byte [] myResponseAuthenticator =
                this.makeRFC2865ResponseAuthenticator(code, identifierByte, length,
                                                    requestAuthenticator, responseAttributeBytes);
            //now compare them
            if((responseAuthenticator.length != 16) ||
                (myResponseAuthenticator.length != 16)){
                //wrong authenticator length asshole!
                throw new RadiusException("Authenticator length is incorrect.");
            }else{
                for (int i = 0; i<responseAuthenticator.length;i++){
                    if (responseAuthenticator[i] != myResponseAuthenticator[i]){
                        //fuck! throw an exception
                        throw new RadiusException("Authenticators do not match, response packet not validated!");
                    }
                }
            }
            RadiusPacket responsePacket = new RadiusPacket(returnCode);
            //RadiusPacket responsePacket = new RadiusResponsePacket(returnCode,identifierByte);
        
        
            //now parse out the responseAttributeBytes into the responseAttributes hashtable
            int attributesLength = responseAttributeBytes.length;
            if (attributesLength > 0){
                int attributeType;
                int attributeLength;
                byte[] attributeValue;
                DataInputStream attributeInput = new DataInputStream(new ByteArrayInputStream(responseAttributeBytes));
                
                for (int left=0; left < attributesLength; ){
                    attributeType = (attributeInput.readByte() & 0xff);
                    attributeLength = attributeInput.readByte() & 0xff;
                    attributeValue = new byte[attributeLength - 2];
                    attributeInput.read(attributeValue, 0, attributeLength - 2);
                    responsePacket.setAttribute(new RadiusAttribute(attributeType, attributeValue));
                    left += attributeLength;
                }
                attributeInput.close();
            }
            return responsePacket;
        }catch(IOException ioex){
            throw new RadiusException(ioex.getMessage());
        }catch(InvalidParameterException ipex){
            throw new RadiusException("Invalid response attributes sent back from server.");
        }finally{
            try{
                input.close();
                bais.close();
            }catch(IOException ignore){}
        }
    }
    /**
     * This method builds a Radius packet for transmission to the Radius Server
     * @param byte code
     * @param byte identifier
     * @param short length
     * @param byte[] requestAuthenticator
     * @param byte[] requestAttributes
     * @exception java.net.UnknownHostException
     * @exception java.io.IOException
     */
    private DatagramPacket composeRadiusPacket(int port, byte code,
                                                byte identifier,
                                                short length,
                                                byte[] requestAuthenticator,
                                                byte[] requestAttributes)
    throws RadiusException{
        ByteArrayOutputStream baos 	= new ByteArrayOutputStream();
        DataOutputStream output 	= new DataOutputStream(baos);
        DatagramPacket packet_out 	= null;

        try{
            //1 byte: Code
            output.writeByte(code);
            //1 byte: identifier
            output.writeByte(identifier);
            //2 byte: Length
            output.writeShort(length);
            //16 bytes: Request Authenticator
            //only write 16 of them if there are more, which there better not be
            output.write(requestAuthenticator, 0, 16);
    
            output.write(requestAttributes, 0, requestAttributes.length);
    
            packet_out = new DatagramPacket(new byte[length], length);
            packet_out.setPort(port);
            packet_out.setAddress(this.hostname);
            packet_out.setLength(length);
    
            packet_out.setData(baos.toByteArray());
            output.close();
            baos.close();
        }catch(IOException ioex){
            throw new RadiusException(ioex.getMessage());
        }
        //won't get here in the case of an exception so we won't return return null or a malformed packet
        return packet_out;
    }
    /**
     * This method sends the outgoing packet and recieves the incoming response
     * @param packet_out java.net.DatagramPacket
     * @param retryCount int Number of retries we will allow
     * @return java.net.DatagramPacket
     * @exception java.io.IOException if there is a problem sending or recieving the packet, i.e recieve timeout
     */
    private DatagramPacket sendReceivePacket(DatagramPacket packet_out, int retry)
    throws RadiusException{
        if (packet_out.getLength() > RadiusPacket.MAX_PACKET_LENGTH){
            throw new RadiusException("Packet too big!");
        }else if (packet_out.getLength() < RadiusPacket.MIN_PACKET_LENGTH){
            throw new RadiusException("Packet too short !");
        }else{
            DatagramPacket packet_in =
                    new DatagramPacket(new byte[RadiusPacket.MAX_PACKET_LENGTH],
                                                    RadiusPacket.MAX_PACKET_LENGTH);
            for (int i = 1; i <= retry; i++){
                try{
                    this.socket.send(packet_out);
                    this.socket.receive(packet_in);
                    return packet_in;
                }catch (IOException ioex){
                    //if we reach the max number of retries throw it back up the stack
                    if (i == retry){
                        throw new RadiusException(ioex.getMessage());
                    }
                }
            }
        }
        //won't get here in the case of an exception so we won't return return null or a malformed packet
        return null;
    }

    /**
     * This method returns a string representation of this
     * <code>RadiusClient</code>.
     *
     * @return a string representation of this object.
     */
    public String toString(){
        StringBuffer sb = new StringBuffer("RadiusClient: HostName = ");
        sb.append(this.getHostname());
        sb.append(" Port = ");
        sb.append(Integer.toString(this.getAuthPort()));
        sb.append(" Shared Secret = ");
        sb.append(this.getSharedSecret());
        return sb.toString();
    }
    /**
     * Compares the specified Object with this <code>RadiusClient</code>
     * for equality.  Returns true if the given object is also a
     * <code>RadiusClient</code> and the two RadiusClient
     * have the same host, port, sharedSecret & username.
     * @param object Object to be compared for equality with this
     *		<code>RadiusClient</code>.
     *
     * @return true if the specified Object is equal to this
     *		<code>RadiusClient</code>.
     */
    public boolean equals(Object object){
        if (object == null){
            return false;
        }
        if (this == object){
            return true;
        }
        if (!(object instanceof RadiusClient)){
            return false;
        }
        RadiusClient that = (RadiusClient)object;
        if ((this.getHostname().equals(that.getHostname())) &&
             (this.getAuthPort() == that.getAuthPort()) &&
             (this.getSharedSecret().equals(that.getSharedSecret()))){
            return true;
        }
        return true;
    }
    /**
     * @return int the hashCode for this <code>RadiusClient</code>
     */
    public int hashCode(){
        StringBuffer sb = new StringBuffer(this.getHostname());
        sb.append(Integer.toString(this.getAuthPort()));
        sb.append(this.getSharedSecret());
        return sb.toString().hashCode();
    }
    /**
     * closes the socket
     *
     */
    protected void closeSocket(){
        this.socket.close();
    }
    /**
     * overrides finalize to close socket and then normal finalize on super class
     */
    public void finalize() throws Throwable{
        this.closeSocket();
        super.finalize();
    }
}
