package net.sourceforge.jradiusclient;

import gnu.getopt.Getopt;
import gnu.getopt.LongOpt;

import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import net.sourceforge.jradiusclient.*;
import net.sourceforge.jradiusclient.attributes.*;
import net.sourceforge.jradiusclient.exception.*;
import net.sourceforge.jradiusclient.jaas.*;
import net.sourceforge.jradiusclient.packets.*;
import net.sourceforge.jradiusclient.util.*;
/**
 * @author <a href="mailto:bloihl@users.sourceforge.net">Robert J. Loihl</a>
 * @version $Revision: 1.18 $
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
        ChapUtil chapUtil = new ChapUtil();
        BufferedReader inputReader = new BufferedReader(new InputStreamReader(System.in));
        basicAuthenticate(rc, chapUtil, inputReader);
        advAuthenticate(rc, chapUtil, inputReader);
    }
    private static void basicAuthenticate(final RadiusClient rc,
            final ChapUtil chapUtil,
            final BufferedReader inputReader){
        try{
            boolean attributes = false, continueTest = true;
            String userName = null, userPass = null, authMethod = null;
            System.out.println("Performing tests using basic classes: ");
            while(continueTest){
                attributes = false;
                RadiusPacket accessRequest = new RadiusPacket(RadiusPacket.ACCESS_REQUEST);
                RadiusAttribute userNameAttribute;
                //prompt user for input
                System.out.print("Username: ");
                userName = inputReader.readLine();
                userNameAttribute = new RadiusAttribute(RadiusAttributeValues.USER_NAME,userName.getBytes());
                accessRequest.setAttribute(userNameAttribute);
                System.out.print("Password: ");
                userPass = inputReader.readLine();
                System.out.print("Authentication method [PAP | chap]: ");
                authMethod = inputReader.readLine();
                if(authMethod.equalsIgnoreCase("chap")){
                    byte[] chapChallenge = chapUtil.getNextChapChallenge(16);
                    accessRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.CHAP_PASSWORD,
                            chapEncrypt(userPass, chapChallenge, chapUtil)));

                    accessRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.CHAP_CHALLENGE,
                            chapChallenge));
                }else{
                    accessRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.USER_PASSWORD,userPass.getBytes()));
                }
                System.out.print("Additional Attributes? [y|N]:");
                boolean more = (inputReader.readLine().equalsIgnoreCase("y"))?true:false;
                while(more){
                    System.out.print("Attribute Type:");
                    int type = Integer.parseInt(inputReader.readLine());
                    System.out.print("AttributeValue:");
                    byte[] value = inputReader.readLine().getBytes();
                    accessRequest.setAttribute(new RadiusAttribute(type, value));
                    System.out.print("Additional Attributes? [y|N]:");
                    more = (inputReader.readLine().equalsIgnoreCase("y"))?true:false;
                }
                RadiusPacket accessResponse = rc.authenticate(accessRequest);
                switch(accessResponse.getPacketType()){
                    case RadiusPacket.ACCESS_ACCEPT:
                        TestRadiusClient.log("User " + userName + " authenticated");
                        basicAccount(rc,userName);
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
                System.out.print("Another Basic Test [ Y | n ]: ");
                authMethod = inputReader.readLine();
                if(authMethod.equalsIgnoreCase("n")){
                    continueTest = false;
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
    private static byte[] chapEncrypt(final String plainText,
                                      final byte[] chapChallenge,
                                      final ChapUtil chapUtil){
        // see RFC 2865 section 2.2
        byte chapIdentifier = chapUtil.getNextChapIdentifier();
        byte[] chapPassword = new byte[17];
        chapPassword[0] = chapIdentifier;
        System.arraycopy(ChapUtil.chapEncrypt(chapIdentifier, plainText.getBytes(),chapChallenge),
                         0, chapPassword, 1, 16);
        return chapPassword;
    }
    private static void basicAccount(final RadiusClient rc,
                                final String userName)
            throws InvalidParameterException, RadiusException{
        RadiusPacket accountRequest = new RadiusPacket(RadiusPacket.ACCOUNTING_REQUEST);
        accountRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.USER_NAME,userName.getBytes()));
        accountRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.ACCT_STATUS_TYPE,new byte[]{0, 0, 0, 1}));
        accountRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.ACCT_SESSION_ID,("bob").getBytes()));
        accountRequest.setAttribute(new RadiusAttribute(RadiusAttributeValues.SERVICE_TYPE,new byte[]{0, 0, 0, 1}));
        RadiusPacket accountResponse = rc.account(accountRequest);
        switch(accountResponse.getPacketType()){
            case RadiusPacket.ACCOUNTING_MESSAGE:
                TestRadiusClient.log("User " + userName + " got ACCOUNTING_MESSAGE response");
                break;
            case RadiusPacket.ACCOUNTING_RESPONSE:
                TestRadiusClient.log("User " + userName + " got ACCOUNTING_RESPONSE response");
                break;
            case RadiusPacket.ACCOUNTING_STATUS:
                TestRadiusClient.log("User " + userName + " got ACCOUNTING_STATUS response");
                break;
            default:
                TestRadiusClient.log("User " + userName + " got invalid response " + accountResponse.getPacketType() );
                break;
        }
    }
    private static void advAuthenticate(final RadiusClient rc,
            final ChapUtil chapUtil,
            final BufferedReader inputReader){
        try{
            boolean attributes = false, continueTest = true;
            String userName = null, userPass = null, authMethod = null;
            System.out.println("Performing tests using advanced classes: ");
            while(continueTest){
                attributes = false;
                RadiusPacket accessRequest = null;
                //prompt user for input
                System.out.print("Username: ");
                userName = inputReader.readLine();
                System.out.print("Password: ");
                userPass = inputReader.readLine();
                System.out.print("Authentication method [PAP | chap]: ");
                authMethod = inputReader.readLine();
                if(authMethod.equalsIgnoreCase("chap")){
                    accessRequest = new ChapAccessRequest(userName, userPass);
                }else{
                    accessRequest = new PapAccessRequest(userName,userPass);
                }
                System.out.print("Additional Attributes? [y|N]:");
                boolean more = (inputReader.readLine().equalsIgnoreCase("y"))?true:false;
                while(more){
                    System.out.print("Attribute Type:");
                    int type = Integer.parseInt(inputReader.readLine());
                    System.out.print("AttributeValue:");
                    byte[] value = inputReader.readLine().getBytes();
                    accessRequest.setAttribute(new RadiusAttribute(type, value));
                    System.out.print("Additional Attributes? [y|N]:");
                    more = (inputReader.readLine().equalsIgnoreCase("y"))?true:false;
                }
                RadiusPacket accessResponse = rc.authenticate(accessRequest);
                switch(accessResponse.getPacketType()){
                    case RadiusPacket.ACCESS_ACCEPT:
                        TestRadiusClient.log("User " + userName + " authenticated");
                    advAccount(rc,userName);
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
                System.out.print("Another Advanced Test [ Y | n ]: ");
                authMethod = inputReader.readLine();
                if(authMethod.equalsIgnoreCase("n")){
                    continueTest = false;
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
    private static void advAccount(final RadiusClient rc,
                                final String userName)
            throws InvalidParameterException, RadiusException{
        RadiusPacket accountRequest = new AccountingRequest(userName, new byte[]{0,0,0,1}, userName);
        RadiusPacket accountResponse = rc.account(accountRequest);
        switch(accountResponse.getPacketType()){
            case RadiusPacket.ACCOUNTING_MESSAGE:
                TestRadiusClient.log("User " + userName + " got ACCOUNTING_MESSAGE response");
                break;
            case RadiusPacket.ACCOUNTING_RESPONSE:
                TestRadiusClient.log("User " + userName + " got ACCOUNTING_RESPONSE response");
                break;
            case RadiusPacket.ACCOUNTING_STATUS:
                TestRadiusClient.log("User " + userName + " got ACCOUNTING_STATUS response");
                break;
            default:
                TestRadiusClient.log("User " + userName + " got invalid response " + accountResponse.getPacketType() );
                break;
        }
    }
    private static void log(final String message){
        System.out.print  ("TestRadiusClient: ");
        System.out.println(message);
    }
}
