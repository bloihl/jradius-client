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
import java.util.Hashtable;
import java.util.Random;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import net.sourceforge.jradiusclient.exception.InvalidParameterException;
import net.sourceforge.jradiusclient.exception.RadiusException;


/**
 *
 * This class implements the NAS characteristics of the RADIUS protocol as
 * specified in RFC 2865 and RFC 2866.
 *
 * Special Thanks to the original creator of the "RadiusClient"
 * <a href="http://augiesoft.com/java/radius/">August Mueller </a>
 * http://augiesoft.com/java/radius/ and to
 * <a href="http://sourceforge.net/projects/jradius-client">Aziz Abouchi</a>
 * for laying the groundwork for the development of this class.
 *
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.6 $
 */
public class RadiusClient implements RadiusValues
{
    private static byte [] NAS_ID;
    private static byte [] NAS_IP;
    private static final int AUTH_LOOP_COUNT = 3;
    private static final int ACCT_LOOP_COUNT = 3;
    private static Object nextIdentifierLock = new Object();
    private static byte nextIdentifier = (byte)0;

    private String userName = "";
    private String sharedSecret = "";
    private String hostname = "";
    private boolean useCHAP = false;
    //This is a weak implementation for Response Attributes as it will only
    //store the last element put into it in the parsing process, whereas some of
    //the elements in the Response packet from the Radius Server may occur
    //multiple times, and we need to store all of them. This needs to be FIXED!
    private Hashtable responseAttributes = new Hashtable();
    private int authenticationPort = 1812;
    private int accountingPort = 1813;
    private DatagramSocket socket = null;
    private int socketTimeout = 6000;
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
     * @param userName java.lang.String
     * @param useCHAP boolean Use CHAP protocol to encrypt Password, false indicates PAP password usage
     * @exception java.net.SocketException If we could not create the necessary socket
     * @exception java.security.NoSuchAlgorithmException If we could not get an
     *                              instance of the MD5 algorithm.
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If an invalid hostname
     *                              (null or empty string), an invalid port
     *                              (port < 0 or port > 65536) or an invalid
     *                              shared secret (null, shared secret can be
     *                              empty string) is passed in.
     */
    public RadiusClient(String hostname, String sharedSecret, String userName, boolean useCHAP)
    throws SocketException, NoSuchAlgorithmException, InvalidParameterException{
        this.setHostname(hostname);
        this.setUserName(userName);
        this.setSharedSecret(sharedSecret);
        //set up the socket for this client
        this.socket = new DatagramSocket();
        this.socket.setSoTimeout(socketTimeout);
        //set up the md5 engine
        this.md5MessageDigest = MessageDigest.getInstance("MD5");
        this.useCHAP = useCHAP;
    }
    /**
     * Constructor allows the user to specify an alternate port for the radius server
     * @param hostname java.lang.String
     * @param authPort int the port to use for authentication requests
     * @param acctPort int the port to use for accounting requests
     * @param sharedSecret java.lang.String
     * @param userName java.lang.String
     * @exception java.net.SocketException If we could not create the necessary socket
     * @exception java.security.NoSuchAlgorithmException If we could not get an
     *                              instance of the MD5 algorithm.
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If an invalid hostname
     *                              (null or empty string), an invalid
     *                              port ( port < 0 or port > 65536)
     *                              or an invalid shared secret (null, shared
     *                              secret can be empty string) is passed in.
     */
    public RadiusClient(String hostname, int authPort, int acctPort, String sharedSecret, String userName, boolean useCHAP)
    throws SocketException, NoSuchAlgorithmException, InvalidParameterException{
        this(hostname, sharedSecret, userName, useCHAP);
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
    public int authenticate(String userPass)
    throws IOException, UnknownHostException, RadiusException, InvalidParameterException {
        return this.authenticate(userPass, null);
    }
    /**
     * This method performs the job of authenticating the specified user against
     * the radius server.
     * @param userPass java.lang.String
     * @param requestAttributes ByteArrayOutputStream
     * @return int Will be one of three possible values RadiusClient.ACCESS_ACCEPT,
     *      RadiusClient.ACCESS_REJECT or RadiusClient.ACCESS_CHALLENGE
     * @exception java.io.IOException
     * @exception java.net.UnknownHostException
     * @exception net.sourceforge.jradiusclient.exception.RadiusException
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException
     */
    public int authenticate(String userPass, ByteArrayOutputStream requestAttributes)
    throws IOException, UnknownHostException, RadiusException, InvalidParameterException {
        //test for validity of userPass
        if (userPass == null){
            throw new InvalidParameterException("Password can not be null!");
        }//else password is a-ok for passing to RADIUS Server
        byte code = RadiusClient.ACCESS_REQUEST;  //1 byte: code
        byte identifier = this.getNextIdentifier();  //1 byte: Identifier can be anything, so should not be constant

        //16 bytes: Request Authenticator
        byte [] requestAuthenticator = this.makeRFC2865RequestAuthenticator();

        // ***************************************************************
        //                          Attributes.
        // ***************************************************************
        if (requestAttributes == null){
            requestAttributes = new ByteArrayOutputStream();
        }
        // USER_NAME
        this.setAttribute(RadiusClient.USER_NAME, this.userName.getBytes(), requestAttributes);
        // USER_PASSWORD
        if(userPass.length() > 0){//otherwise we don't add it to the Attributes
            if (userPass.length() > 16){
                userPass = userPass.substring(0, 16);
            }
            if(this.useCHAP){
                //(encryptPass gives ArrayIndexOutOfBioundsException if password is of zero length)
                this.setAttribute(RadiusClient.USER_PASSWORD, userPass.length(), this.encryptPass(userPass, requestAuthenticator), requestAttributes);
            }else{
                this.setAttribute(RadiusClient.USER_PASSWORD, userPass.length(), userPass.getBytes(), requestAttributes);
            }
        }
        //set a STATE attribute IF it is there (for Challenge responses)
        try{
            this.setAttribute(RadiusClient.STATE, this.getStateAttributeFromResponse(), requestAttributes);
        }catch(RadiusException rex){
            //no state attribute was set, so we go merrily on our way
        }
        // Set the NAS-Identifier
        this.setAttribute(RadiusClient.NAS_IDENTIFIER, RadiusClient.NAS_ID, requestAttributes);
        // Length of Packet is computed as follows, 20 bytes (corresponding to
        // length of code + Identifier + Length + Request Authenticator) +
        // each attribute has a length computed as follows: 1 byte for the type +
        // 1 byte for the length of the attribute + length of attribute bytes
        short length = (short) (RadiusClient.RADIUS_HEADER_LENGTH + requestAttributes.size() );

        DatagramPacket packet =
            this.composeRadiusPacket(this.getAuthPort(), code, identifier, length, requestAuthenticator, requestAttributes.toByteArray());
        // now send the request and recieve the response
        int responseCode = 0;
        if ((packet = this.sendReceivePacket(packet, RadiusClient.AUTH_LOOP_COUNT)) != null){
            switch(this.checkRadiusPacket(packet,identifier, requestAuthenticator)){
            case RadiusClient.ACCESS_ACCEPT:
                responseCode = RadiusClient.ACCESS_ACCEPT;
                break;
            case RadiusClient.ACCESS_REJECT:
                responseCode = RadiusClient.ACCESS_REJECT;
                break;
            case RadiusClient.ACCESS_CHALLENGE:
                responseCode = RadiusClient.ACCESS_CHALLENGE;
                break;
            default:
                throw new RadiusException("Invalid response recieved from the RADIUS Server.");
            }
        }
        //destroy userPass in memory?
        return responseCode;
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
        byte[] service = new byte[] {0,0,0,1};
        try{
            return this.account(service,sessionID);
        }catch(RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
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
        byte[] service = new byte[] {0,0,0,3};
        try{
            return this.account(service,sessionID);
        }catch(RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
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
        byte[] service = new byte[] {0,0,0,2};
        try{
            return this.account(service,sessionID);
        }catch(RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
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
        byte[] service = new byte[] {0,0,0,7};
        try{
            return this.account(service,sessionID);
        }catch(RadiusException rex){
            //only happens when service is too long or short so we ignore it
        }
        return false;
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
        byte[] service = new byte[] {0,0,0,8};
        try{
            return this.account(service,sessionID);
        }catch(RadiusException rex){
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
        byte code = RadiusClient.ACCOUNTING_REQUEST;
        byte identifier = this.getNextIdentifier();
        if(service.length != 4){
            throw new RadiusException("The service byte array must have a length of 4");
        }
        if((sessionId == null) || (sessionId == "")){
            sessionId = "session" + this.userName;
        }
        ByteArrayOutputStream requestAttributes = new ByteArrayOutputStream();
        this.setAttribute(RadiusClient.USER_NAME, this.userName.getBytes(), requestAttributes);
        this.setAttribute(RadiusClient.NAS_IDENTIFIER, RadiusClient.NAS_ID, requestAttributes);
        this.setAttribute(RadiusClient.ACCT_STATUS_TYPE, service, requestAttributes);	// Acct-Status-Type
        this.setAttribute(RadiusClient.ACCT_SESSION_ID, sessionId.getBytes(),requestAttributes);
        this.setAttribute(RadiusClient.SERVICE_TYPE, service, requestAttributes);

        // Length of Packet is computed as follows, 20 bytes (corresponding to
        // length of code + Identifier + Length + Request Authenticator) +
        // each attribute has a length computed as follows: 1 byte for the type +
        // 1 byte for the length of the attribute + length of attribute bytes
        short length = (short) (RadiusClient.RADIUS_HEADER_LENGTH + requestAttributes.size());
        byte[] requestAuthenticator =
            this.makeRFC2866RequestAuthenticator(code, identifier, length, requestAttributes.toByteArray());

        DatagramPacket packet =
            this.composeRadiusPacket(this.getAcctPort(), code, identifier, length, requestAuthenticator,requestAttributes.toByteArray());
        //send the request / recieve the response
        if ((packet = this.sendReceivePacket(packet, RadiusClient.ACCT_LOOP_COUNT)) != null) {
            if(RadiusClient.ACCOUNTING_RESPONSE == this.checkRadiusPacket(packet,identifier, requestAuthenticator)){
                return true;
            }
        }
        //else we didn't get back a response which indicates failure to
        //communicate successfully with the RADIUS Accounting
        return false;
    }
    /**
     * This method encrypts the user password according to RFC 2865
     * @param userPass java.lang.String the password to encrypt
     * @param requestAuthenticator byte[] the requestAuthenicator to use in the encryption
     * @return byte[] the byte array containing the encrypted password
     */
    private byte [] encryptPass(String userPass, byte [] requestAuthenticator) {
        // encrypt the password
        //the password must be a multiple of 16 bytes and less than or equal
        //to 128 bytes if it isn't a multiple of 16 bytes fill itout with zeroes
        //to make it a multiple of 16 bytes if it is greater than 128 bytes
        //truncate it at 128

        // Transformation de la chaine en tableau d'octet pour hachage MD5.
        byte userPassBytes[] = userPass.getBytes();
        // declare the byte array to hold the final product
        byte encryptedPass[] = null;

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
                //add the next 16 bytes of the user password (at this point they are unencrypted)
                this.md5MessageDigest.update(encryptedPass, i, i+16);
                // get the md5 hash( bn = MD5(S + c(i-1)) ).
                bn = this.md5MessageDigest.digest();
                for (int j = 0; i < 16; j++) {
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
        return this.hostname;
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
        }else{//everything is a-ok
            this.hostname = hostname;
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
    public void setAuthPort(int port) throws InvalidParameterException
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
    public void setAcctPort(int port) throws InvalidParameterException
    {
        if ((port > 0) && (port < 65536)){
            this.accountingPort = port;
        }else{
            throw new InvalidParameterException("Port value out of range!");
        }
    }
    /**
     * This method returns the current user name to be used for authentication
     * @return java.lang.String
     */
    public String getUserName() {
        return this.userName;
    }
    /**
     * This method sets the user name to be used for authentication
     * @param user_name java.lang.String
     * @exception net.sourceforge.jradiusclient.exception.InvalidParameterException If the username is null,
     *                          empty or all blanks
     */
    public void setUserName(String username) throws InvalidParameterException {
        if (username == null){
            throw new InvalidParameterException("User Name can not be null!");
        }else{//everything is a-ok
            this.userName = username;
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
    public void setTimeout(int socket_timeout) throws InvalidParameterException {
        if (socket_timeout < 0){
            throw new InvalidParameterException("A negative timeout value is not allowed!");
        }else{//everything is a-ok
            this.socketTimeout = socket_timeout;
        }
    }
    /**
     * This method extracts the reply message returned by a RADIUS Server and
     * supplies it to the user, who should them use it to build a new password
     * and re-authenticate.
     *@return java.lang.String the challenge message to display to the user
     *@exception net.sourceforge.jradiusclient.exception.RadiusException
     */
    public String getReplyMessage() throws RadiusException{
        if(this.responseAttributes == null){
            throw new RadiusException("No Response Attributes have been set.");
        }
        byte[] messageBytes = (byte[])this.responseAttributes.get(new Integer(RadiusClient.REPLY_MESSAGE));
        if ((messageBytes == null) || (messageBytes.length == 0)){
            throw new RadiusException("No Reply Message has been set.");
        }
        return new String(messageBytes);
    }
    /**
     * This method extracts the Challenge message returned by a RADIUS Server and
     * supplies it to the user, who should them use it to build a new password
     * and re-authenticate.
     *@return java.lang.String the challenge message to display to the user
     *@exception net.sourceforge.jradiusclient.exception.RadiusException
     */
    public String getChallengeMessage() throws RadiusException{
        return this.getReplyMessage();
    }
    /**
     * This method extracts the SessionTimeout returned by a RADIUS Server
     *@return java.lang.Integer the session timeout for the user
     *@exception net.sourceforge.jradiusclient.exception.RadiusException
     */
    public Integer getSessionTimeout() throws RadiusException{
        if(this.responseAttributes == null){
            throw new RadiusException("No Response Attributes have been set.");
        }
        byte[] sessiontimeoutBytes = (byte[])this.responseAttributes.get(new Integer(RadiusClient.SESSION_TIMEOUT));
        if ((sessiontimeoutBytes == null) || (sessiontimeoutBytes.length == 0)){
            throw new RadiusException("No Session Timeout has been set.");
        }
        return this.attributeBytesToInteger(sessiontimeoutBytes);
    }
    /**
     * This method extracts the Framed IP Address returned by a RADIUS Server
     *@return java.lang.String the Framed Ip Address
     *@exception net.sourceforge.jradiusclient.exception.RadiusException
     */
    public String getFramedIPAddress() throws RadiusException{
        if(this.responseAttributes == null){
            throw new RadiusException("No Response Attributes have been set.");
        }
        byte[] ipaddrBytes = (byte[])this.responseAttributes.get(new Integer(RadiusClient.FRAMED_IP_ADDRESS));
        if ((ipaddrBytes == null) || (ipaddrBytes.length == 0)){
            throw new RadiusException("No Framed Ip Address has been set.");
        }
        return this.attributeBytesToIPAddr(ipaddrBytes);
    }
    /**
     *
     */
    private Integer attributeBytesToInteger(byte[] input){
        int value = 0, tmp =0;
        for(int i = 0; i<input.length;i++){
            tmp = input[i] & 0x7F;
            if((input[i]&80000000) != 0){
                tmp |=0x80;
            }
            value = (256 * value) + tmp;
        }
        return new Integer(value);
    }
    /**
     *
     */
    private String attributeBytesToIPAddr(byte[] input)throws RadiusException{
        if (input.length > 4){
            throw new RadiusException("Invalid IP Address - too many bytes");
        }
        StringBuffer ipaddr = new StringBuffer();
        for(int i =0; i<4;i++){
            if((input[i]&80000000)!=0){
                ipaddr.append((input[i] & 0x7F) | 0x80);
            }else{
                ipaddr.append((input[i] & 0x7F));
            }
            if (i != 3){
                ipaddr.append(".");
            }
        }
        return ipaddr.toString();
    }
    /**
     * This method returns the bytes sent in the STATE attribute of the RADIUS
     * Server's response to a request
     *@return java.lang.String the challenge message to display to the user
     *@exception net.sourceforge.jradiusclient.exception.RadiusException
     */
    private byte[] getStateAttributeFromResponse() throws RadiusException{
        if(this.responseAttributes == null){
            throw new RadiusException("No Response Attributes have been set.");
        }
        byte[] stateBytes = (byte[])this.responseAttributes.get(new Integer(RadiusClient.STATE));
        if ((stateBytes == null) || (stateBytes.length == 0)){
            throw new RadiusException("No State Attribute has been set.");
        }
        return stateBytes;
    }
    /**
     * This method is used to set a byte array attribute in the Request Attributes
     * portion of the packet. Use one of the other two methods to set simple attributes.
     * This method should only be called directly to set a password attribute,
     * where the length expected by the radius server is the actual length of the
     * password not the length of the MD5 encrypted byte array (16 bytes) that go
     * into the packet.
     * @param type int attribute type
     * @param length int length of attribute, this is normally the length of the byte array
     *                   but in the case of the password attribute it is the actual length
     *                   of the password not the length of the MD5 hashed 16 byte value actually
     *                   passed to the radius server
     * @param attribute byte[] the actual attribute byte array
     * @param requestAttributes ByteArrayOutputStream the ByteArrayOutputStreamto write the attribute to
     */
    private void setAttribute(int type, int length, byte [] attribute, ByteArrayOutputStream requestAttributes)
    {
        //1 byte: Type
        requestAttributes.write(type);

        //1 byte: length of the Type plus 2 bytes for the rest of this attirbute.
        requestAttributes.write(length + 2);

        //Value.length() bytes: the actual Value.
        requestAttributes.write(attribute, 0, length);
    }
    /**
     * This method is used to set a byte array attribute in the Request Attributes
     * portion of the packet.
     * @param type int attribute type
     * @param attribute byte[] the actual attribute byte array
     * @param requestAttributes ByteArrayOutputStream the ByteArrayOutputStreamto write the attribute to
     */
    public void setAttribute(int type, byte [] attribute, ByteArrayOutputStream requestAttributes)
    {
        this.setAttribute(type, attribute.length, attribute, requestAttributes);
    }
    /**
     * This method is used to set a single byte attribute in the Request Attributes
     * portion of the packet.
     * @param type int attribute type
     * @param attribute byte the actual attribute byte
     * @param requestAttributes ByteArrayOutputStream the ByteArrayOutputStreamto write the attribute to
     */
    private void setAttribute(int type, byte attribute, ByteArrayOutputStream requestAttributes) {
        byte [] attributeArray = {attribute};
        this.setAttribute(type, attributeArray.length, attributeArray, requestAttributes);
    }
    /**
     * @param packet java.net.DatagramPacket
     * @param requestIdentifier byte
     * @param requestAuthenticator byte[]
     * @return int the code value from the radius response packet
     * @exception net.sourceforge.jradiusclient.exception.RadiusException
     * @exception java.io.IOException
     */
    private int checkRadiusPacket(DatagramPacket packet,
                                        byte requestIdentifier,
                                        byte[] requestAuthenticator)
    throws IOException, RadiusException{
        int returnCode = -1;
        int packetLength = packet.getLength();
        ByteArrayInputStream bais = new ByteArrayInputStream(packet.getData());
        DataInputStream input = new DataInputStream(bais);

/* ***************************************************************
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     code      |  identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Response Authenticator                    |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-
*****************************************************************/
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
        byte[] responseAttributeBytes = new byte[length - RadiusClient.RADIUS_HEADER_LENGTH];
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
        //now parse out the responseAttributeBytes into the responseAttributes hashtable
        int attributesLength = responseAttributeBytes.length;
        if (attributesLength > 0){
            Integer attributeType;
            int attributeLength;
            byte[] attributeValue;
            DataInputStream attributeInput = new DataInputStream(new ByteArrayInputStream(responseAttributeBytes));
            this.responseAttributes.clear();//thread issues???
            for (int left=0; left < attributesLength; ){
                attributeType = new Integer(attributeInput.readByte() & 0xff);
                attributeLength = attributeInput.readByte() & 0xff;
                attributeValue = new byte[attributeLength - 2];
                attributeInput.read(attributeValue, 0, attributeLength - 2);
                this.responseAttributes.put(attributeType, attributeValue);
                left += attributeLength;
            }
            attributeInput.close();
        }
        input.close();
        bais.close();
        return returnCode;
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
    throws UnknownHostException, IOException{
        ByteArrayOutputStream baos 	= new ByteArrayOutputStream();
        DataOutputStream output 	= new DataOutputStream(baos);
        DatagramPacket packet_out 	= null;
// A)
/* ***************************************************************
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Request Authenticator                     |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-

   Code

      The Code field is one octet, and identifies the type of RADIUS
      packet.  When a packet is received with an invalid Code field, it
      is silently discarded.

      RADIUS Codes (decimal) are assigned as follows:

        1       Access-Request
        2       Access-Accept
        3       Access-Reject
        4       Accounting-Request
        5       Accounting-Response
       11       Access-Challenge
       12       Status-Server (experimental)
       13       Status-Client (experimental)
      255       Reserved

   Codes 4 and 5 are covered in the RADIUS Accounting document [5].
   Codes 12 and 13 are reserved for possible use, but are not further
   mentioned here.
*******************************************************************/
//1 byte: Code
        output.writeByte(code);
// B)
/* *****************************************************************
   Identifier

      The Identifier field is one octet, and aids in matching requests
      and replies.  The RADIUS server can detect a duplicate request if
      it has the same client source IP address and source UDP port and
      Identifier within a short span of time.
*******************************************************************/
//1 byte: identifier
        output.writeByte(identifier);
// C)
/* ****************************************************************
   Length

      The Length field is two octets.  It indicates the length of the
      packet including the Code, Identifier, Length, Authenticator and
      Attribute fields.  Octets outside the range of the Length field
      MUST be treated as padding and ignored on reception.  If the
      packet is shorter than the Length field indicates, it MUST be
      silently discarded.  The minimum length is 20 and maximum length
      is 4096.
******************************************************************/
//2 byte: Length
        output.writeShort(length);
// D)
/* ****************************************************************
   Request Authenticator

         In Access-Request Packets, the Authenticator value is a 16
         octet random number, called the Request Authenticator.  The
         value SHOULD be unpredictable and unique over the lifetime of a
         secret (the password shared between the client and the RADIUS
         server), since repetition of a request value in conjunction
         with the same secret would permit an attacker to reply with a
         previously intercepted response.  Since it is expected that the
         same secret MAY be used to authenticate with servers in
         disparate geographic regions, the Request Authenticator field
         SHOULD exhibit global and temporal uniqueness.

         The Request Authenticator value in an Access-Request packet
         SHOULD also be unpredictable, lest an attacker trick a server
         into responding to a predicted future request, and then use the
         response to masquerade as that server to a future Access-
         Request.

         Although protocols such as RADIUS are incapable of protecting
         against theft of an authenticated session via realtime active
         wiretapping attacks, generation of unique unpredictable
         requests can protect against a wide range of active attacks
         against authentication.

         The NAS and RADIUS server share a secret.  That shared secret
         followed by the Request Authenticator is put through a one-way
         MD5 hash to create a 16 octet digest value which is xored with
         the password entered by the user, and the xored result placed
         in the User-Password attribute in the Access-Request packet.
         See the entry for User-Password in the section on Attributes
         for a more detailed description.
******************************************************************/
//16 bytes: Request Authenticator
//only write 16 of them if there are more, which there better not be
        output.write(requestAuthenticator, 0, 16);

        output.write(requestAttributes, 0, requestAttributes.length);

        packet_out = new DatagramPacket(new byte[length], length);
        packet_out.setPort(port);
        packet_out.setAddress(InetAddress.getByName(this.hostname));
        packet_out.setLength(length);

        packet_out.setData(baos.toByteArray());
        output.close();
        baos.close();
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
    throws IOException, RadiusException{
        if (packet_out.getLength() > RadiusClient.MAX_PACKET_LENGTH){
            throw new RadiusException("Packet too big!");
        }else if (packet_out.getLength() < RadiusClient.MIN_PACKET_LENGTH){
            throw new RadiusException("Packet too short !");
        }else{
            DatagramPacket packet_in =
                    new DatagramPacket(new byte[RadiusClient.MAX_PACKET_LENGTH],
                                                RadiusClient.MAX_PACKET_LENGTH);
            for (int i = 1; i <= retry; i++){
                try{
                    this.socket.send(packet_out);
                    this.socket.receive(packet_in);
                    return packet_in;
                }catch (IOException ioex){
                    //if we reach the max number of retries throw it back up the stack
                    if (i == retry){
                        throw ioex;
                    }
                }
            }
        }
        //won't get here in the case of an exception so we won't return return null or a malformed packet
        return null;
    }
    /**
     * This method returns the next identifier for use in building Radius Packets.
     * @return byte
     */
    private static byte getNextIdentifier(){
        byte identifier = 0;
        synchronized(RadiusClient.nextIdentifierLock){
            identifier = RadiusClient.nextIdentifier;
            RadiusClient.nextIdentifier++;
        }
        return identifier;
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
        sb.append(" User Name = ");
        sb.append(this.getUserName());
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
             (this.getSharedSecret().equals(that.getSharedSecret())) &&
             this.getUserName().equals(that.getUserName())){
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
        sb.append(this.getUserName());
        return sb.hashCode();
    }
}
