import java.util.HashMap;

public interface RadiusValues
{

/****************  Debut Constant Packet Type Codes  **************************/
public static final int Access_Request		= 1;
public static final int Access_Accept 		= 2;
public static final int Access_Reject		= 3;
public static final int Accounting_Request	= 4;
public static final int Accounting_Response	= 5;
public static final int Accounting_Status	= 6;
public static final int Password_Request	= 7;
public static final int Password_Accept	= 8;
public static final int Password_Reject	= 9;
public static final int Accounting_Message	= 10;
public static final int Access_Challenge	= 11;
public static final int Status_Server		= 12;	// (experimental)
public static final int Status_Client		= 13;	// (experimental)
public static final int Reserved		= 255;
/*******************  Fin Constant Packet Type Codes  *************************/

/*******************  Debut Constant Attribute Types  *************************/
public static final int USER_NAME       		= 1;
public static final int USER_PASSWORD   		= 2;
public static final int CHAP_Password			= 3;
public static final int NAS_IP_Address			= 4;
public static final int NAS_Port			= 5;
public static final int Service_Type			= 6;
public static final int Framed_Protocol			= 7;
public static final int Framed_IP_Address		= 8;
public static final int Framed_IP_Netmask		= 9;
public static final int Framed_Routing			= 10;
public static final int Filter_Id			= 11;
public static final int Framed_MTU			= 12;
public static final int Framed_Compression		= 13;
public static final int Login_IP_Host			= 14;
public static final int Login_Service			= 15;
public static final int Login_TCP_Port			= 16;
							//17      (unassigned)
public static final int Reply_Message			= 18;
public static final int Callback_Number			= 19;
public static final int Callback_Id			= 20;
							//21      (unassigned)
public static final int Framed_Route			= 22;
public static final int Framed_IPX_Network		= 23;
public static final int State				= 24;
public static final int Class				= 25;
public static final int Vendor_Specific			= 26;
public static final int Session_Timeout			= 27;
public static final int Idle_Timeout			= 28;
public static final int Termination_Action		= 29;
public static final int Called_Station_Id		= 30;
public static final int Calling_Station_Id		= 31;
public static final int NAS_Identifier			= 32;
public static final int Proxy_State			= 33;
public static final int Login_LAT_Service		= 34;
public static final int Login_LAT_Node			= 35;
public static final int Login_LAT_Group			= 36;
public static final int Framed_AppleTalk_Link		= 37;
public static final int Framed_AppleTalk_Network	= 38;
public static final int Framed_AppleTalk_Zone		= 39;

//40_59   (reserved for accounting)
public static final int Acct_tatus_Type		= 40;
public static final int Acct_elay_Tme			= 41;
public static final int Acct_Input_ctets		= 42;
public static final int Acct_Output_Octets		= 43;
public static final int Acct_Session_Id		= 44;
public static final int Acct_Authentic			= 45;
public static final int Acct_Session_Time		= 46;
public static final int Acct_Input_Packets		= 47;
public static final int Acct_Output_Packets		= 48;
public static final int Acct_Terminate_Cause		= 49;
public static final int Acct_Multi_Session_Id		= 50;
public static final int Acct_Link_Count		= 51;
public static final int Acct_Input_Gigawords		= 52;
public static final int Acct_Output_Gigawords	= 53;
public static final int Event_Timestamp		= 55;

public static final int CHAP_Challenge		= 60;
public static final int NAS_Port_Type		= 61;
public static final int Port_Limit			= 62;
public static final int Login_LAT_Port		= 63;

public static final int ARAP_Password		= 70;
public static final int ARAP_Features			= 71;
public static final int ARAP_Zone_Access		= 72;
public static final int ARAP_Security			= 73;
public static final int ARAP_Security_Data		= 74;
public static final int Password_Retry		= 75;
public static final int Prompt				= 76;
public static final int Connect_Info			= 77;
public static final int Configuration_Token		= 78;
public static final int EAP_Message			= 79;
public static final int Message_Authenticator		= 80;
public static final int ARAP_Challenge_Response	= 84;
public static final int Acct_Interim_Interval		= 85;
public static final int NAS_Port_Id			= 87;
public static final int Framed_Pool			= 88;
/********************  Fin Constant Attribute Types  **************************/

/*******************  Debut Constant Attribute Types  *************************/
// Service-Type ou User Types
public static final int Login				=  1;
public static final int Framed				=  2;
public static final int Callback_Login			=  3;
public static final int Callback_Framed		=  4;
public static final int Outbound			=  5;
public static final int Administrative			=  6;
public static final int NAS_Prompt			=  7;
public static final int Authenticate_Only		=  8;
public static final int Callback_NAS_Prompt		=  9;
public static final int Call_Check			= 10;
public static final int Callback_Administrative	= 11;

// Framed-Protocol
public static final int PPP					= 1;
public static final int SLIP					= 2;
public static final int ARAP					= 3;
public static final int Gandalf_SLML				= 4;
public static final int Xylogics_proprietary_IPX_SLIP	= 5;
public static final int X75_Synchronous			= 6;

// Framed-Routing
public static final int None			= 0;
public static final int Broadcast		= 1;
public static final int Listen			= 2;
public static final int Broadcast_Listen	= 3;

// Framed-Compression
//public static final int None					= 0;
public static final int VJ_TCP_IP_header_compression	= 1;
public static final int IPX_header_compression		= 2;
public static final int Stac_LZS_compression			= 3;

// Login-Service
public static final int Telnet			= 0;
public static final int Rlogin			= 1;
public static final int TCP_Clear		= 2;
public static final int PortMaster		= 3;
public static final int LAT			= 4;
public static final int X25_PAD		= 5;
public static final int X25_T3POS		= 7;
public static final int TCP_Clear_Quiet	= 8;

// Termination-Action
public static final int Default		= 0;
public static final int RADIUS_Request	= 1;

// NAS-Port-Type
public static final int Async			=  0;
public static final int Sync			=  1;
public static final int ISDN_Sync		=  2;
public static final int ISDN_Async_V120	=  3;
public static final int ISDN_Async_V110	=  4;
public static final int Virtual			=  5;
public static final int PIAFS			=  6;
public static final int HDLC_Clear_Channel	=  7;
public static final int X25			=  8;
public static final int X75			=  9;
public static final int G3_Fax			= 10;
public static final int SDSL			= 11;
public static final int ADSL_CAP		= 12;
public static final int ADSL_DMT		= 13;
public static final int IDSL			= 14;
public static final int Ethernet			= 15;
public static final int xDSL			= 16;
public static final int Cable			= 17;
public static final int Wireless_Other		= 18;
public static final int Wireless_IEEE_802_11	= 19;

/*******************    Fin Constant Attribute Types  *************************/
}
