package net.sourceforge.jradiusclient;

import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import net.sourceforge.jradiusclient.exception.*;
/**
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.8 $
 */
public class TestRadiusClient{
    public static String getUsage(){
        return "usage: RadiusClient server authPort acctPort secret user password [calling-station-id]";
    }

    public static void main(String [] args)
    {
        if ((args.length < 6) || (args.length > 7))
        {
            TestRadiusClient.log(getUsage());
            System.exit(2);
        }
        int authport = 0 ;
        int acctport = 0 ;
        try{
            authport = Integer.parseInt(args[1]);
            acctport = Integer.parseInt(args[2]);
        }catch (NumberFormatException nfex){
            TestRadiusClient.log("port must be a positive integer!");
            TestRadiusClient.log(getUsage());
            System.exit(3);
        }

        RadiusClient rc = null;
        try{
            rc = new RadiusClient(args[0], authport,acctport, args[3],args[4]);
        }catch(java.net.SocketException soex){
            TestRadiusClient.log("Unable to create Radius Client due to failure to create socket!");
            TestRadiusClient.log(getUsage());
            System.exit(4);
        }catch(java.security.NoSuchAlgorithmException nsaex){
            TestRadiusClient.log("Unable to create Radius Client due to failure to create MD5 MessageDigest!");
            TestRadiusClient.log(getUsage());
            System.exit(5);
        }catch(InvalidParameterException ivpex){
            TestRadiusClient.log("Unable to create Radius Client due to invalid parameter!");
            TestRadiusClient.log(ivpex.getMessage());
            TestRadiusClient.log(getUsage());
            System.exit(6);
        }
        String userPass = args[5];
        byte[] callingStationId = null;
        if(args.length > 6 ){//the seventh one should be calling station ID
            callingStationId = args[6].getBytes();
        }
        try{
            boolean returned = TestRadiusClient.authenticate(rc, userPass, callingStationId);
            if (returned){
                TestRadiusClient.log("------------------------------------------------------");
                returned = rc.startAccounting(args[5]);
                if (returned){
                    TestRadiusClient.log("Accounting start succeeded.");
                }else{
                    TestRadiusClient.log("Accounting start failed.");
                }
                TestRadiusClient.log("------------------------------------------------------");
                returned = rc.stopAccounting(args[5]);
                if (returned){
                    TestRadiusClient.log("Accounting stop succeeded.");
                }else{
                    TestRadiusClient.log("Accounting stop failed.");
                }
                TestRadiusClient.log("------------------------------------------------------");
            }
        }catch(InvalidParameterException ivpex){
            TestRadiusClient.log(ivpex.getMessage());
        }catch(java.net.UnknownHostException uhex){
            TestRadiusClient.log(uhex.getMessage());
        }catch(java.io.IOException ioex){
            TestRadiusClient.log(ioex.getMessage());
        }catch(RadiusException rex){
            TestRadiusClient.log(rex.getMessage());
        }
    }
    public static boolean authenticate(RadiusClient rc, String userPass,  byte[] callingStationId) throws InvalidParameterException,
    java.net.UnknownHostException, java.io.IOException, RadiusException{
        int returnCode;
        if(callingStationId != null){
            ByteArrayOutputStream reqAttributes = new ByteArrayOutputStream();
            try{
                rc.setUserAttribute(RadiusClient.CALLING_STATION_ID, callingStationId, reqAttributes);
            }catch(InvalidParameterException ivpex){
                System.out.println(ivpex);
            }
            returnCode = rc.authenticate(userPass, reqAttributes);
        }else{
            returnCode = rc.authenticate(userPass);
        }
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

    private void setSIPAttributes(RadiusClient rc, ByteArrayOutputStream reqAttributes) throws InvalidParameterException {
        rc.setUserAttribute(RadiusClient.DIGEST_RESPONSE, "0c02a1cc5ec9a986aaa7232bb975faffa".getBytes(), reqAttributes);

             rc.setUserSubAttribute(
                 RadiusClient.DIGEST_ATTRIBUTE,
                 RadiusClient.SIP_REALM,
                 "buddyphone".getBytes(),
                 reqAttributes
             );

             rc.setUserSubAttribute(
                 RadiusClient.DIGEST_ATTRIBUTE,
                 RadiusClient.SIP_USER_NAME,
                 "koehler".getBytes(),
                 reqAttributes
             );

             rc.setUserSubAttribute(
                 RadiusClient.DIGEST_ATTRIBUTE,
                 RadiusClient.SIP_NONCE,
                 "1a80ff0a".getBytes(),
                 reqAttributes
             );

             rc.setUserSubAttribute(
                 RadiusClient.DIGEST_ATTRIBUTE,
                 RadiusClient.SIP_URI,
                 "sip:buddyphone.com:5060".getBytes(),
                 reqAttributes
             );

             rc.setUserSubAttribute(
                 RadiusClient.DIGEST_ATTRIBUTE,
                 RadiusClient.SIP_METHOD,
                 "REGISTER".getBytes(),
                 reqAttributes
             );

             rc.setUserSubAttribute(
                 RadiusClient.DIGEST_ATTRIBUTE,
                 RadiusClient.SIP_ALGORITHM,
                 "MD5".getBytes(),
                 reqAttributes
             );
    }
}
