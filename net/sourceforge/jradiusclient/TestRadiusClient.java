package net.sourceforge.jradiusclient;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

import java.io.BufferedInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import net.sourceforge.jradiusclient.exception.*;
/**
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.12 $
 */
public class TestRadiusClient{
    public static String getUsage(){
        return "usage: TestRadiusClient -s RadiusServer -S sharedSecret [--authPort=1812] [--acctPort=1813]";
    }

    public static void main(String [] args)
    {
        int authport = 1812 ;
        int acctport = 1813;
        String host = "localhost",sharedSecret = null;
        StringBuffer portSb = new StringBuffer();
        LongOpt[] longOpts = {new LongOpt("authPort",LongOpt.REQUIRED_ARGUMENT,portSb,1),
            new LongOpt("acctPort",LongOpt.REQUIRED_ARGUMENT,portSb,2)};
        Getopt gOpt = new Getopt("TestRadiusClient",args,"s:S:",longOpts,false);
        gOpt.setOpterr(true);
        int c;
        while((c = gOpt.getopt()) != -1){
            switch(c){
                case 's':
                    host = gOpt.getOptarg();
                    break;
                case 'S':
                    sharedSecret = gOpt.getOptarg();
                    break;
                case 1:
                    authport = (new Integer(portSb.toString())).intValue();
                    break;
                case 2:
                    acctport = (new Integer(portSb.toString())).intValue();
                    break;
                case '?':
                    break;//getopt already printed an error
                default:
                    System.err.println(getUsage());
            }
        }

        RadiusClient rc = null;
        try{
            rc = new RadiusClient(host, authport,acctport, sharedSecret);
        }catch(RadiusException rex){
            TestRadiusClient.log(rex.getMessage());
            TestRadiusClient.log(getUsage());
            System.exit(4);
        }catch(InvalidParameterException ivpex){
            TestRadiusClient.log("Unable to create Radius Client due to invalid parameter!");
            TestRadiusClient.log(ivpex.getMessage());
            TestRadiusClient.log(getUsage());
            System.exit(5);
        }
        String userName = null, userPass = null, authMethod = null;
        boolean attributes = false;
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(System.in));
        try{
            while(true){
                attributes = false;
                RadiusPacket accessRequest = new RadiusPacket(RadiusPacket.ACCESS_REQUEST);
                RadiusAttribute userNameAttribute;
                //prompt user for input
                System.out.print("Username: ");
                userNameAttribute = new RadiusAttribute(RadiusAttributeValues.USER_NAME,inputReader.readLine().getBytes());
                accessRequest.setAttribute(userNameAttribute);
                System.out.print("Password: ");
                userPass = inputReader.readLine();
                System.out.print("Authentication method [PAP | chap]: ");
                authMethod = inputReader.readLine();
                if(authMethod.equalsIgnoreCase("chap")){
                    byte[] chapChallenge = ("my Challenge bytes").getBytes();
                    accessRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.CHAP_PASSWORD,chapEncrypt(userPass,chapChallenge)));
                    accessRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.CHAP_CHALLENGE,chapChallenge));
                }else{
                    accessRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.USER_PASSWORD,userPass.getBytes()));
                }
    //            System.out.print("Additional Attributes? [y|N]:");
    //            System.out.print("Attribute Type:");
    //            System.out.print("AttributeValue:");
                RadiusPacket accessResponse = rc.authenticate(accessRequest);
                switch(accessResponse.getPacketType()){
                    case RadiusPacket.ACCESS_ACCEPT:
                        TestRadiusClient.log("User " + userName + " authenticated");
                        break;
                    case RadiusPacket.ACCESS_REJECT:
                        TestRadiusClient.log("User " + userName + " NOT authenticated");
                        break;
                    case RadiusPacket.ACCESS_CHALLENGE:
                        String reply = new String(accessResponse.getAttribute(RadiusAttributeValues.REPLY_MESSAGE).getValue());
                        TestRadiusClient.log("User " + userName + " Challenged with " + reply);
                        break;
                    default:
                        TestRadiusClient.log("Whoa, what kind of RadiusPacket is this " + accessResponse.getPacketType());
                        break;
                }
            }
        }catch(InvalidParameterException ivpex){
            TestRadiusClient.log(ivpex.getMessage());
        }catch(RadiusException rex){
            TestRadiusClient.log(rex.getMessage());
        }catch(IOException ioex){
            TestRadiusClient.log(ioex.getMessage());
        }
    }
    private static byte[] chapEncrypt(String plainText, byte[] chapChallenge){
        //pretend we are a client who is encrypting his password with a random
        //challenge from the NAS, see RFC 2865 section 2.2
        //generate next chapIdentifier
        byte chapIdentifier = (byte)1;//todo randomize
        byte[] chapResponse = plainText.getBytes();// if we get a exception we will send back plaintext
        try{
            MessageDigest md5MessageDigest = MessageDigest.getInstance("MD5");
            md5MessageDigest.reset();
            md5MessageDigest.update(chapIdentifier);
            md5MessageDigest.update(plainText.getBytes());
            chapResponse = md5MessageDigest.digest(chapChallenge);
            //now we are the NAS, composing the CHAP-Password Attribute, which consists
            //of the chapIdentifier byte followed by the 16 byte output of the MD5
            //algorithm received "over the wire" from the user
            byte[] chapPassword = new byte[17];
            chapPassword[0] = chapIdentifier;
            System.arraycopy(chapResponse,0,chapPassword,1,16);
        }catch(NoSuchAlgorithmException nsaex){
            TestRadiusClient.log(nsaex.getMessage());
        }
        return chapResponse;
    }
    private static void log(String message)
    {
        System.out.print  ("TestRadiusClient: ");
        System.out.println(message);
    }

//    private void setSIPAttributes(RadiusClient rc, ByteArrayOutputStream reqAttributes) throws InvalidParameterException {
//        rc.setUserAttribute(RadiusClient.DIGEST_RESPONSE, "0c02a1cc5ec9a986aaa7232bb975faffa".getBytes(), reqAttributes);
//
//             rc.setUserSubAttribute(
//                 RadiusClient.DIGEST_ATTRIBUTE,
//                 RadiusClient.SIP_REALM,
//                 "buddyphone".getBytes(),
//                 reqAttributes
//             );
//
//             rc.setUserSubAttribute(
//                 RadiusClient.DIGEST_ATTRIBUTE,
//                 RadiusClient.SIP_USER_NAME,
//                 "koehler".getBytes(),
//                 reqAttributes
//             );
//
//             rc.setUserSubAttribute(
//                 RadiusClient.DIGEST_ATTRIBUTE,
//                 RadiusClient.SIP_NONCE,
//                 "1a80ff0a".getBytes(),
//                 reqAttributes
//             );
//
//             rc.setUserSubAttribute(
//                 RadiusClient.DIGEST_ATTRIBUTE,
//                 RadiusClient.SIP_URI,
//                 "sip:buddyphone.com:5060".getBytes(),
//                 reqAttributes
//             );
//
//             rc.setUserSubAttribute(
//                 RadiusClient.DIGEST_ATTRIBUTE,
//                 RadiusClient.SIP_METHOD,
//                 "REGISTER".getBytes(),
//                 reqAttributes
//             );
//
//             rc.setUserSubAttribute(
//                 RadiusClient.DIGEST_ATTRIBUTE,
//                 RadiusClient.SIP_ALGORITHM,
//                 "MD5".getBytes(),
//                 reqAttributes
//             );
//    }
}
