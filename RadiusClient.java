import java.io.*;
import java.net.*;
import java.util.*;
import java.awt.event.*;
import java.math.BigInteger;
import DictionaryParser;

public class RadiusClient implements RadiusValues
{
        private static int     	port = 1812,
                        	secondary_port = 1645,
                        	socket_timeout = 6000;

        private String  user_name = "",
                        user_pass = "",
                        shared_secret = "",
                        hostname = "",
                        secondary_hostname = "";

	byte Code, Identifier;
	short Length;
	ByteArrayOutputStream RequestAttributes = new ByteArrayOutputStream();
	byte [] RequestAuthenticator;
	static byte [] NAS_Id;

	static DatagramSocket socket = null;
	DatagramPacket packet_in = null;

	private static Hashtable Values = new Hashtable();

	public RadiusClient() { }
	
	public RadiusClient(String hostname)
	{
		this.hostname 	= hostname;
	}
	
	public RadiusClient(String hostname, int port)
	{
		this.hostname = hostname;
		this.port = port;
	}
	
	public RadiusClient(String	hostname, 
					int port, 
					String secondary_hostname, 
					int secondary_port)
	{
		this.hostname 	= hostname;
		this.port 	= port;
		this.secondary_hostname = secondary_hostname;
		this.secondary_port = secondary_port;
	}
	
	public int authenticate(String user_name, String user_pass)
	{
		this.user_name = user_name;
		this.user_pass = user_pass;
		return authenticate();
	}
	
	public int authenticate()
	{
		// Seul les 16 premiers octets sont pris en compte car le Request Authenticator
		// a un capacité de 16 octets seulement !!!

		if (user_pass.length() > 16)
			user_pass = user_pass.substring(0, 16);
			Code = Access_Request;                                              //1 byte: Code
			Identifier = 71;                                                    //1 byte: Identifier
                        // Longueur du paquet, rajoutant les 2 bytes correspondant aux Types et Lengths de chaque Attribut
                        //	+ 20 bytes correspondant à Code + Identifier + Length + Request Authenticator.
                        //        20		=	    1   +    1       +   2    +       16
			Length = (short) ( 	   user_name.length() + 2
						 + user_pass.length() + 2
						 + NAS_Id.length + 2
						 + 20);                                     //2 byte: Length
			RequestAuthenticator = makeRFC2865RequestAuthenticator();           //16 bytes: Request Authenticator

                        /*****************************************************************
                                                    Les Attributs.
                        *****************************************************************/
			setAttribute(USER_NAME, user_name.getBytes(), RequestAttributes);   // USER_NAME
                        // USER_PASSWORD
			setAttribute(USER_PASSWORD, user_pass.length() , encryptPass(user_pass, RequestAuthenticator), RequestAttributes);
			setAttribute(NAS_Identifier, NAS_Id, RequestAttributes);            // NAS-Identifier

			DatagramPacket paquet = new DatagramPacket(new byte[Length], Length);

			paquet = ComposeRadiusPacket();
			PrintRadiusPacket(paquet);

                        System.out.println();
			System.out.println("Emission d'un packet Radius >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
			SendPacket(paquet);            // emission de la requete

			paquet = ReceivePacket();      // reception de la requete
			if (paquet == null)
				return -1;
			else
			{
				System.out.println("Decodage d'un packet Radius reçu **************************************");
				return PrintRadiusPacket(paquet);
			}
	}
	
	private byte [] encryptPass(String user_pass, byte [] request_authenticator)
	{
	// Cryptage de mots de passes de longueurs comprises entre 16 et 128 caractéres.

	// Le mot de passe doit etre de taille multiple de 16  
        // et inferieur a 128, si ce n'est pas un multiple de 16,
        // completer par des "0" jusqu'à obtention d'une taille compatible,   
        // si la taille est superieur a 128, tronquer le paquet a une taille de 128

        	byte user_passB[] = user_pass.getBytes();	// Transformation de la chaine en tableau d'octet pour hachage MD5.

		byte UPass[] = null;				// Creation du recipient de l'user password
		if (user_passB.length < 128)
		{
                	if (user_passB.length % 16 == 0)
                    		UPass = new byte[user_passB.length];			// taille multiple de 16
			else UPass = new byte[((user_passB.length / 16) * 16) + 16];	// taille non multiple de 16
		}
		else UPass = new byte[128];					// taille compris entre 16 et 128 pas plus !!!

                System.arraycopy(user_passB, 0, UPass, 0, user_passB.length);   // copie de l'user password dans son recipient
                for(int i = user_passB.length; i < UPass.length; i++)
                    UPass[i] = 0;                               		// on completion par des "0"

                MD5 md5 = new MD5();
		md5.Update(shared_secret.getBytes());		// Ajout du mots de passe partagé avec le serveur RADIUS.
		md5.Update(request_authenticator);		// Ajout du Request Authenticator.
		byte bn[] = md5.Final();			// Resultat du hachage( b1 = MD5(S + RA) ).
   
		for (int i = 0; i < 16; i++)
                    UPass[i] = (byte)(bn[i] ^ UPass[i]);        // Nous effectuons les fameux XOR selon la RFC.
                if (UPass.length > 16)
                {
                    for (int i = 16; i < UPass.length; i+=16)
                    {
                        md5.Init();
                        md5.Update(shared_secret.getBytes());		// Ajout du mots de passe partagé avec le serveur RADIUS.
                        md5.Update(UPass, i, i+16);
                        bn = md5.Final();                               // Resultat du hachage( bn = MD5(S + c(i-1)) ).
                        for (int j = 0; i < 16; j++)
                            UPass[i+j] = (byte)(bn[j] ^ UPass[i+j]);    // Nous effectuons les fameux XOR selon la RFC.
                    }
                }
                return UPass;
        }
	
	private byte[] makeRFC2865RequestAuthenticator()
	{
		byte [] request_authenticator = new byte [16];
		
		Random r = new Random();
		
		for (int i = 0; i < 16; i++)
			request_authenticator[i] = (byte) r.nextInt();
		
		MD5 md5 = new MD5();
        	md5.Update(shared_secret.getBytes());
                md5.Update(request_authenticator);
        
		return md5.Final();
	}

        private byte[] makeRFC2866RequestAuthenticator()
        {
                byte [] request_authenticator = new byte [16];

                for (int i = 0; i < 16; i++)
                        request_authenticator[i] = 0;

                MD5 md5 = new MD5();

		md5.Update((byte)Code);
		md5.Update((byte)Identifier);
		md5.Update((byte)(Length >> 8));
		md5.Update((byte)(Length & 0xff));
		md5.Update(request_authenticator, 0, request_authenticator.length);
		md5.Update(RequestAttributes.toByteArray(), 0, RequestAttributes.toByteArray().length);
		md5.Update(shared_secret.getBytes());

                return md5.Final(); 
        }
	
	public String getHostname()
	{
		return hostname;
	}
	
	public String getSecondaryHostname()
	{
		return hostname;
	}
	
	public void setHostname(String hostname)
	{
		this.hostname = hostname;
	}
	
	public void setSecondaryHostname(String secondary_hostname)
	{
		this.secondary_hostname = secondary_hostname;
	}
	
	public int getPort()
	{
		return port;
	}
	
    public int getSecondaryPort()
    {
	return secondary_port;
    }
	
    public void setPort(int port)
    {
	this.port = port;
    }
	
    public void setSecondaryPort(int secondary_port)
    {
	this.secondary_port = secondary_port;
    }
	
    public void setUserName(String user_name)
    {
    	this.user_name = user_name;
    }
    
    public String getUserName()
    {
    	return user_name;
    }
    
    public String getUserPass()
    {
    	return user_pass;
    }

    public void setUserPass(String user_pass)
    {
    	this.user_pass = user_pass;
    }
    
    public String getSharedSecret()
    {
    	return shared_secret;
    }

    public void setSharedSecret(String shared_secret)
    {
    	this.shared_secret = shared_secret;
    }
	
    public int getTimeout()
    {
	return socket_timeout;
    }
	
    public void setTimeout(int socket_timeout)
    {
	this.socket_timeout = socket_timeout;
    }
    
    private static final void log(String s)
    {
        System.out.print  ("RadiusClient: ");
        System.out.println(s);
    }

    public void setAttribute(int Type, int Length, byte [] Value, ByteArrayOutputStream RequestAttributes)
    {
        try
        {
        //1 byte: Type
                RequestAttributes.write(Type);

        //1 byte: length of the Type plus 2 bytes for the rest of this attirbute.
                RequestAttributes.write(Length+2);

        //Value.length() bytes: the actual Value.
                RequestAttributes.write(Value, 0, Length);
        }
        catch (Exception e)
        {
                System.out.println("java.io.InterruptedIOException : "+e.toString());
                e.printStackTrace(System.out);
        }
    }

    public void setAttribute(int Type, byte [] Value, ByteArrayOutputStream RequestAttributes)
    {
	setAttribute(Type, Value.length, Value, RequestAttributes);
    }

    public void setAttribute(int Type, byte Value, ByteArrayOutputStream RequestAttributes)
    {
        //1 byte: Type
                RequestAttributes.write(Type);

        //1 byte: length of the Type plus 2 bytes for the rest of this attirbute.
                RequestAttributes.write(3);

        //1 byte: the actual Value.
                RequestAttributes.write(Value);
    }
    
	public int PrintRadiusPacket(DatagramPacket Packet)
    	{
	int return_code = -1;
	String AttributeValue = "";
	int Packet_length = Packet.getLength();

	System.out.println("Packet Received Length = "+Packet_length);
	try
	{
        	ByteArrayInputStream bais = new ByteArrayInputStream(Packet.getData());
        	DataInputStream input = new DataInputStream(bais);

/*****************************************************************
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Code      |  Identifier   |            Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Response Authenticator                    |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Attributes ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-
*****************************************************************/

        	return_code = input.readByte() & 0xff;
		System.out.print("Packet Type Code: " + return_code);
		System.out.println(" "+((Hashtable) Values.get("Packet-Type")).get( new Integer (return_code)));

                System.out.println("Identifier : "+(input.readByte() & 0xff));

                System.out.println("Length : "+(input.readShort() & 0xffff));

		//Avance rapide de 16 bytes
		//Car pour passer aux attributs, il faut passer l'entete (20 bytes)
		// Code + Identifier + Length + Response Authenticator = 20
		//  1   +     1      +    2   +          16            = 20
		//Nous avons lu les 4 premier => 20 - 4 = 16.
		input.skipBytes(16);

        	for (int left=0; left < (Packet_length - 20); left++)
        	{
			System.out.println("+");

        		int attribute_type = input.readByte() & 0xff;
			String TmpString = (String)((Hashtable) Values.get("ATTRIBUTE")).get( new Integer (attribute_type));
                	System.out.println("Attribute Type = "+attribute_type+" "+TmpString );

                	int attribute_length = input.readByte() & 0xff;
                	System.out.println("Attribute Length = "+attribute_length);

                	byte[] attribute_value= new byte[attribute_length - 2];
                	input.read(attribute_value, 0, attribute_length - 2);

			if ( (TmpString.startsWith("string")) || (TmpString.startsWith("text")) )
			{
				if ((attribute_type == 2) || (attribute_type == 3))
                                	AttributeValue = "Pass : XXXXXXXX";
				else
					AttributeValue = new String (attribute_value);
			}
			else if (TmpString.startsWith("integer"))
			{
				int R=0;
				int tmp;
                		for (int i=0; i<attribute_value.length; i++)
				{
					tmp = attribute_value[i] & 0x7F;
					if((attribute_value[i]&80000000)!=0)
                                                tmp = tmp | 0x80;
					R = (256*R) + tmp;
					AttributeValue = ""+R;
				}

				TmpString = TmpString.substring(TmpString.lastIndexOf(" ")+1);
				if (Values.containsKey(TmpString))
					AttributeValue =  AttributeValue +" "+(String)((Hashtable) Values.get(TmpString)).get( new Integer (R));
			}
			else if (TmpString.startsWith("ipaddr"))
                        {
    				for(int i=0;i<4;i++)
				{
					if((attribute_value[i]&80000000)!=0)
						AttributeValue =  AttributeValue + ((attribute_value[i] & 0x7F) | 0x80);
					else AttributeValue =  AttributeValue + (attribute_value[i] & 0x7F);
      					if(i!=3)
						AttributeValue =  AttributeValue + '.';
    				}

			}
			System.out.println("Attribute Value = "+AttributeValue);
			AttributeValue = "";

                	left += attribute_length;
		}
	}
	catch (Exception e)
        {
                System.out.println("java.io.InterruptedIOException : "+e.toString());
                e.printStackTrace(System.out);
        }
	return return_code;
    	}
	
	private DatagramPacket ComposeRadiusPacket()
	{
		ByteArrayOutputStream baos 	= null;
		DataOutputStream output 	= null;
		DatagramPacket packet_out 	= null;

                try
		{
                        baos    = new ByteArrayOutputStream();
                        output  = new DataOutputStream(baos);
// A)
/*****************************************************************
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
                        output.writeByte(Code);
// B)
/*******************************************************************
   Identifier

      The Identifier field is one octet, and aids in matching requests
      and replies.  The RADIUS server can detect a duplicate request if
      it has the same client source IP address and source UDP port and
      Identifier within a short span of time.
*******************************************************************/
//1 byte: Identifier
                        output.writeByte(Identifier);
// C)
/******************************************************************
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
                        output.writeShort(Length);
// D)
/******************************************************************
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
                        output.write(RequestAuthenticator, 0, 16);

			output.write(RequestAttributes.toByteArray(), 0, RequestAttributes.size());

                        packet_out = new DatagramPacket(new byte[Length], Length);
                        packet_out.setPort(port);
                        packet_out.setAddress(InetAddress.getByName(hostname));
                        packet_out.setLength(Length);

                        packet_out.setData(baos.toByteArray());
                }
                catch (java.io.InterruptedIOException e)
                {
                        System.out.println("Packet timed out");
                }
                catch (Exception e)
                {
                        System.out.println("java.io.InterruptedIOException : "+e.toString());
                        e.printStackTrace(System.out);
                }
                return packet_out;
	}

	public int account()
	{
		Code = Accounting_Request;
		Identifier = 72;
		byte [] Service = new byte [4]; 
		Service[0] = 0;
		Service[1] = 0;
                Service[2] = 0;
                Service[3] = 1;
		Length = (short) ( user_name.length() + 2
                                                 + NAS_Id.length + 2
						 + 6
						 + "session-id".getBytes().length + 2
						 + Service.length + 2
                                                 + 20);

		RequestAttributes.reset();
                setAttribute(USER_NAME, user_name.getBytes(), RequestAttributes);
                setAttribute(NAS_Identifier, NAS_Id, RequestAttributes);
                setAttribute(40, Service, RequestAttributes);					// Acct-Status-Type (virer service !!!)
		setAttribute(44, "session-id".getBytes(), RequestAttributes);
                setAttribute(6, Service, RequestAttributes);

                RequestAuthenticator = makeRFC2866RequestAuthenticator();

                DatagramPacket paquet = new DatagramPacket(new byte[Length], Length);

                paquet = ComposeRadiusPacket();
                PrintRadiusPacket(paquet);

                System.out.println();
                System.out.println("émission d'un accounting packet Radius >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>");
                SendPacket(paquet);

// Fin du formatage et d'émission du paquet (Access Request)

// Debut de la réception
                paquet = ReceivePacket();
		if (paquet == null)
			return -1;
		else
		{
                	System.out.println("Decodage d'un packet Radius reçu **************************************");
                	return PrintRadiusPacket(paquet);
		}
        }

	private void SendPacket(DatagramPacket Packet)
	{
		if (Packet.getLength() > 4096)
			System.out.println("Packet too long !!!");
		else if (Packet.getLength() < 20)
                        System.out.println("Packet too short !!!");
		else
		{
			try
			{
				socket.send(Packet);
			}
                	catch (java.io.InterruptedIOException e)
                	{
                        	System.out.println("Packet timed out");
                	}
			catch (Exception e)
                	{
                        	System.out.println("java.io.InterruptedIOException : "+e.toString());
                        	e.printStackTrace(System.out);
                	}
		}
	}

        private DatagramPacket ReceivePacket()
        {
		packet_in = new DatagramPacket(new byte[4096], 4096);

		try
		{
			socket.receive(packet_in);
		}
                catch (java.io.InterruptedIOException e)
                {
                        System.out.println("Packet timed out");
			return null;
                }
		catch (Exception e)
                {
                        System.out.println("java.io.InterruptedIOException : "+e.toString());
                        e.printStackTrace(System.out);
			return null;
                }
		return packet_in;
	}
        
        public static void main(String [] args)
        {
            if (args.length < 5)
            {
                System.out.println("usage: RadiusClient server port secret id password");
                System.exit(2);
            }
        RadiusClient rc = new RadiusClient();

        try
        {
		NAS_Id = ((java.net.InetAddress.getLocalHost()).getHostName()).getBytes();
                socket = new DatagramSocket();
                socket.setSoTimeout(socket_timeout);

        }
        catch (Exception e)
        {
                System.out.println("java.io.InterruptedIOException : "+e.toString());
                e.printStackTrace(System.out);
        }

	DictionaryParser.setConstant("dictionary", Values);

        rc.setHostname(args[0]);
        rc.setPort(Integer.parseInt(args[1]));
        rc.setSharedSecret(args[2]);
        rc.setUserName(args[3]);
        rc.setUserPass(args[4]);

        System.out.println("Port Auth : "+rc.getPort());        
	System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++");
        log("Authentication returned: " + rc.authenticate(args[3], args[4]));
        System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++++++++");

        System.out.println();
	rc.setPort(1813);
	System.out.println("Port Acct : "+rc.getPort());
	System.out.println("------------------------------------------------------");
        log("Authentication returned: " + rc.account());
        System.out.println("------------------------------------------------------");
    }

}
