package net.sourceforge.jradiusclient;

import java.io.InputStreamReader;
import java.io.BufferedReader;
/**
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.1 $
 */
public class TestRadiusClient{
    public static void main(String [] args)
    {
        if (args.length < 4)
        {
            TestRadiusClient.log("usage: RadiusClient server authPort acctPort secret user [password]");
            System.exit(2);
        }
        int authport = 0 ;
        int acctport = 0 ;
        try{
            authport = Integer.parseInt(args[1]);
            acctport = Integer.parseInt(args[2]);
        }catch (NumberFormatException nfex){
            TestRadiusClient.log("port must be a positive integer!");
            TestRadiusClient.log("usage: RadiusClient server authPort acctPort secret user password");
            System.exit(3);
        }
        RadiusClient rc = null;
        try{
            rc = new RadiusClient(args[0], authport,acctport, args[3],args[4]);
        }catch(java.net.SocketException soex){
            TestRadiusClient.log("Unable to create Radius Client due to failure to create socket!");
            TestRadiusClient.log("usage: RadiusClient server authPort acctPort secret user [password]");
            System.exit(4);
        }catch(java.security.NoSuchAlgorithmException nsaex){
            TestRadiusClient.log("Unable to create Radius Client due to failure to create MD5 MessageDigest!");
            TestRadiusClient.log("usage: RadiusClient server authPort acctPort secret user [password]");
            System.exit(5);
        }catch(com.flatrock.util.InvalidParameterException ivpex){
            TestRadiusClient.log("Unable to create Radius Client due to invalid parameter!");
            TestRadiusClient.log(ivpex.getMessage());
            TestRadiusClient.log("usage: RadiusClient server authPort acctPort secret user [password]");
            System.exit(6);
        }
        String userPass;
        if (args.length == 6){
            userPass = args[5];
        }else{
            userPass = "";
        }
        try{
            boolean returned = TestRadiusClient.authenticate(rc, userPass);
            if (returned){
                TestRadiusClient.log("------------------------------------------------------");
                returned = rc.account();
                if (returned){
                    TestRadiusClient.log("Accounting succeeded.");
                }else{
                    TestRadiusClient.log("Accounting failed.");
                }
                TestRadiusClient.log("------------------------------------------------------");
            }
        }catch(com.flatrock.util.InvalidParameterException ivpex){
            TestRadiusClient.log(ivpex.getMessage());
        }catch(java.net.UnknownHostException uhex){
            TestRadiusClient.log(uhex.getMessage());
        }catch(java.io.IOException ioex){
            TestRadiusClient.log(ioex.getMessage());
        }catch(com.flatrock.util.radius.RadiusException rex){
            TestRadiusClient.log(rex.getMessage());
        }
    }
    public static boolean authenticate(RadiusClient rc, String userPass) throws com.flatrock.util.InvalidParameterException,
    java.net.UnknownHostException, java.io.IOException, RadiusException{
        int returnCode = rc.authenticate(userPass);
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
            returned = TestRadiusClient.authenticate(rc, userPass);
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
}
