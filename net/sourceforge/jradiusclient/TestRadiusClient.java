package net.sourceforge.jradiusclient;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

import java.io.BufferedInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import net.sourceforge.jradiusclient.exception.*;
/**
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.11 $
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
        String userName, userPass, authMethod;
        boolean attributes = false;
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(System.in));
        try{
            while(true){
                attributes = false;
                //prompt user for input
                System.out.print("Username: ");
                userName = inputReader.readLine();
                System.out.print("Password:");
                userPass = inputReader.readLine();
                System.out.print("Authentication method [PAP | chap]:");
                authMethod = inputReader.readLine();
    //            System.out.print("Additional Attributes? [y|N]:");
    //            System.out.print("Attribute Type:");
    //            System.out.print("AttributeValue:");
    //            try{
    //                boolean returned = TestRadiusClient.chapAuthenticate(rc, userPass);
    //                if (returned){
    //                    TestRadiusClient.log("------------------------------------------------------");
    //                    /*returned = rc.startAccounting(args[5]);
    //                    if (returned){
    //                        TestRadiusClient.log("Accounting start succeeded.");
    //                    }else{
    //                        TestRadiusClient.log("Accounting start failed.");
    //                    }
    //                    TestRadiusClient.log("------------------------------------------------------");
    //                    returned = rc.stopAccounting(args[5]);
    //                    if (returned){
    //                        TestRadiusClient.log("Accounting stop succeeded.");
    //                    }else{
    //                        TestRadiusClient.log("Accounting stop failed.");
    //                    }
    //                    */
    //                    TestRadiusClient.log("------------------------------------------------------");
    //                }
    //            }catch(InvalidParameterException ivpex){
    //                TestRadiusClient.log(ivpex.getMessage());
    //            }catch(RadiusException rex){
    //                TestRadiusClient.log(rex.getMessage());
    //            }
            }
        }catch(IOException ioex){
            
        }
    }
    public static boolean authenticate(RadiusClient rc, String userPass) throws InvalidParameterException,
    java.net.UnknownHostException, java.io.IOException, RadiusException, NoSuchAlgorithmException{
        int returnCode;
        returnCode = rc.authenticate(userPass);
        boolean returned = false;
        TestRadiusClient.log("++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        switch (returnCode){
        case RadiusClient.ACCESS_ACCEPT:
            TestRadiusClient.log("Authenticated");
            returned = true;
            break;
        case RadiusClient.ACCESS_REJECT:
            TestRadiusClient.log("Not Authenticated");
            returned = false;
            break;
        case RadiusClient.ACCESS_CHALLENGE:
            TestRadiusClient.log(rc.getChallengeMessage());
            //wait for user input
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            userPass = br.readLine();
            returned = TestRadiusClient.authenticate(rc, userPass, callingStationId);
            break;
        default:
            TestRadiusClient.log("How the hell did we get here?");
            returned = false;
            break;
        }
        TestRadiusClient.log("++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        return returned;
    }
    public static boolean chapAuthenticate(RadiusClient rc, String userPass) throws InvalidParameterException,
    java.net.UnknownHostException, java.io.IOException, RadiusException, NoSuchAlgorithmException{
        int returnCode;
        //pretend we are a client who is encrypting his password with a random
        //challenge from the NAS, see RFC 2865 section 2.2
        String chapChallenge = new String("myChallenge");
        //generate next chapIdentifier
        byte chapIdentifier = (byte)1;
        MessageDigest md5MessageDigest = MessageDigest.getInstance("MD5");
        md5MessageDigest.reset();
        md5MessageDigest.update(chapIdentifier);
        md5MessageDigest.update(userPass.getBytes());
        byte[] chapResponse = md5MessageDigest.digest(chapChallenge.getBytes());
        //now we are the NAS, composing the CHAP-Password Attribute, which consists
        //of the chapIdentifier byte followed by the 16 byte output of the MD5
        //algorithm received "over the wire" from the user, this is arguably the
        //place for a method in the RadiusClient class
        //puiblic void setChapPassword(int chapIdent, byte[] chapResponse,ByteArrayOutputStream requestAttributes){
        byte[] chapPassword = new byte[17];
        chapPassword[0] = chapIdentifier;
        System.arraycopy(chapResponse,0,chapPassword,1,16);
        //now set userPass to "" to avoid sending it over the wire
        userPass = "";
        ByteArrayOutputStream reqAttributes = new ByteArrayOutputStream();
        //add CHAP attributes
        rc.setUserAttribute(RadiusAttributeValues.CHAP_PASSWORD, chapPassword, reqAttributes);
        rc.setUserAttribute(RadiusAttributeValues.CHAP_CHALLENGE, chapChallenge.getBytes(), reqAttributes);
        returnCode = rc.authenticate(userPass, reqAttributes);

        boolean returned = false;
        TestRadiusClient.log("++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        switch (returnCode){
        case RadiusClient.ACCESS_ACCEPT:
            TestRadiusClient.log("Authenticated");
            returned = true;
            break;
        case RadiusClient.ACCESS_REJECT:
            TestRadiusClient.log("Not Authenticated");
            returned = false;
            break;
        case RadiusClient.ACCESS_CHALLENGE:
            TestRadiusClient.log(rc.getChallengeMessage());
            //wait for user input
            BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
            userPass = br.readLine();
            returned = TestRadiusClient.authenticate(rc, userPass, callingStationId);
            break;
        default:
            TestRadiusClient.log("How the hell did we get here?");
            returned = false;
            break;
        }
        TestRadiusClient.log("++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        return returned;
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
