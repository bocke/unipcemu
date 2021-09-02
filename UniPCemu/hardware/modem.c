/*

Copyright (C) 2019 - 2021 Superfury

This file is part of UniPCemu.

UniPCemu is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

UniPCemu is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with UniPCemu.  If not, see <https://www.gnu.org/licenses/>.
*/

//Only when not using Windows, include types first!
#ifndef _WIN32
#include "headers/types.h" //Basic types first! Also required for system detection!
#endif

//Compile without PCAP support, but with server simulation when NOPCAP and PACKERSERVER_ENABLED is defined(essentially a server without login information and PCap support(thus no packets being sent/received))?
/*
#define NOPCAP
#define PACKETSERVER_ENABLED
*/

#if defined(PACKETSERVER_ENABLED)
#define HAVE_REMOTE

//Missing for various systems?
#if !defined(_WIN32) || defined(__MINGW32__) || defined(__MINGW64__)
//On Linux and MinGW!
typedef unsigned char u_char;
typedef unsigned int u_int;
typedef unsigned short u_short;
#endif

//WPCAP is defined by support when using winpcap! Don't define it here anymore!
#ifndef NOPCAP
#ifdef _WIN32
#ifndef WPCAP
//Temporarily define WPCAP!
#define WPCAP
#define WPCAP_WASNTDEFINED
#endif
#ifndef WIN32
//Make sure WIN32 is also defined with _WIN32 for PCAP to successfully be used!
#define WIN32
#endif
#endif
#include <pcap.h>
#ifdef WPCAP_WASNTDEFINED
//Undefine the temporary WPCAP define!
#undef WPCAP
#endif
#ifdef _WIN32
#include <tchar.h>
#endif
#endif
#endif

#include "headers/types.h" //Basic types first! Also required for system detection!

//Remaining headers
#include "headers/hardware/modem.h" //Our basic definitions!

#include "headers/support/zalloc.h" //Allocation support!
#include "headers/hardware/uart.h" //UART support for the COM port!
#include "headers/support/fifobuffer.h" //FIFO buffer support!
#include "headers/support/locks.h" //Locking support!
#include "headers/bios/bios.h" //BIOS support!
#include "headers/support/tcphelper.h" //TCP support!
#include "headers/support/log.h" //Logging support for errors!
#include "headers/support/highrestimer.h" //High resolution timing support for cleaning up DHCP!

#if defined(PACKETSERVER_ENABLED)
#include <stdint.h>
#include <stdlib.h>

//Nice little functionality for dynamic loading of the Windows libpcap dll!

#ifdef _WIN32

// DLL loading
#define pcap_sendpacket(A,B,C)			PacketSendPacket(A,B,C)
#define pcap_close(A)					PacketClose(A)
#define pcap_freealldevs(A)				PacketFreealldevs(A)
#define pcap_open(A,B,C,D,E,F)			PacketOpen(A,B,C,D,E,F)
#define pcap_next_ex(A,B,C)				PacketNextEx(A,B,C)
#define pcap_findalldevs_ex(A,B,C,D)	PacketFindALlDevsEx(A,B,C,D)
#define pcap_geterr(A)	PacketGetError(A)
#define pcap_datalink(A) PacketDataLink(A)

int (*PacketSendPacket)(pcap_t*, const u_char*, int) = 0;
void (*PacketClose)(pcap_t*) = 0;
void (*PacketFreealldevs)(pcap_if_t*) = 0;
pcap_t* (*PacketOpen)(char const*, int, int, int, struct pcap_rmtauth*, char*) = 0;
int (*PacketNextEx)(pcap_t*, struct pcap_pkthdr**, const u_char**) = 0;
int (*PacketFindALlDevsEx)(char*, struct pcap_rmtauth*, pcap_if_t**, char*) = 0;
char* (*PacketGetError)(pcap_t*) = 0;
int	(*PacketDataLink)(pcap_t*) = 0;

char pcap_src_if_string[] = PCAP_SRC_IF_STRING;

byte LoadPcapLibrary() {
	// remember if we've already initialized the library
	static HINSTANCE pcapinst = (HINSTANCE)-1;
	if (pcapinst != (HINSTANCE)-1) {
		return (pcapinst != NULL);
	}

	// init the library
	pcapinst = LoadLibrary("WPCAP.DLL");
	if (pcapinst == NULL) {
		return FALSE;
	}
	FARPROC psp;

#ifdef __MINGW32__
	// C++ defines function and data pointers as separate types to reflect
	// Harvard architecture machines (like the Arduino). As such, casting
	// between them isn't portable and GCC will helpfully warn us about it.
	// We're only running this code on Windows which explicitly allows this
	// behaviour, so silence the warning to avoid confusion.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif

	psp = GetProcAddress(pcapinst, "pcap_sendpacket");
	if (!PacketSendPacket) PacketSendPacket =
		(int(__cdecl*)(pcap_t*, const u_char*, int))psp;

	psp = GetProcAddress(pcapinst, "pcap_close");
	if (!PacketClose) PacketClose =
		(void(__cdecl*)(pcap_t*)) psp;

	psp = GetProcAddress(pcapinst, "pcap_freealldevs");
	if (!PacketFreealldevs) PacketFreealldevs =
		(void(__cdecl*)(pcap_if_t*)) psp;

	psp = GetProcAddress(pcapinst, "pcap_open");
	if (!PacketOpen) PacketOpen =
		(pcap_t * (__cdecl*)(char const*, int, int, int, struct pcap_rmtauth*, char*)) psp;

	psp = GetProcAddress(pcapinst, "pcap_next_ex");
	if (!PacketNextEx) PacketNextEx =
		(int(__cdecl*)(pcap_t*, struct pcap_pkthdr**, const u_char**)) psp;

	psp = GetProcAddress(pcapinst, "pcap_findalldevs_ex");
	if (!PacketFindALlDevsEx) PacketFindALlDevsEx =
		(int(__cdecl*)(char*, struct pcap_rmtauth*, pcap_if_t**, char*)) psp;

	psp = GetProcAddress(pcapinst, "pcap_geterr");
	if (!PacketGetError) PacketGetError =
		(char* (__cdecl*)(pcap_t*)) psp;

	psp = GetProcAddress(pcapinst, "pcap_datalink");
	if (!PacketDataLink) PacketDataLink =
		(int (__cdecl*)(pcap_t*)) psp;

#ifdef __MINGW32__
#pragma GCC diagnostic pop
#endif

	if (PacketFindALlDevsEx == 0 || PacketNextEx == 0 || PacketOpen == 0 ||
		PacketFreealldevs == 0 || PacketClose == 0 || PacketSendPacket == 0 ||

		PacketGetError == 0) {
		dolog("ethernetcard","Incorrect or non-functional WinPcap version.");
		pcapinst = NULL;
		return FALSE;
	}

	return TRUE;
}

#endif

//End of the libpcap support for Windows!

#endif

/*

Packet server support!

*/

extern BIOS_Settings_TYPE BIOS_Settings; //Currently used settings!

/* packet.c: functions to interface with libpcap/winpcap for ethernet emulation. */

byte PacketServer_running = 0; //Is the packet server running(disables all emulation but hardware)?
uint8_t maclocal[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //The MAC address of the modem we're emulating!
uint8_t packetserver_broadcastMAC[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }; //The MAC address of the modem we're emulating!
byte packetserver_sourceMAC[6]; //Our MAC to send from!
byte packetserver_gatewayMAC[6]; //Gateway MAC to send to!
byte packetserver_defaultstaticIP[4] = { 0,0,0,0 }; //Static IP to use?
byte packetserver_broadcastIP[4] = { 0xFF,0xFF,0xFF,0xFF }; //Broadcast IP to use?
byte packetserver_usedefaultStaticIP = 0; //Use static IP?
char packetserver_defaultstaticIPstr[256] = ""; //Static IP, string format

typedef struct
{
	byte* buffer;
	uint_32 size;
	uint_32 length;
} MODEM_PACKETBUFFER; //Packet buffer for PAD packets!

//Authentication data and user-specific data!
typedef struct
{
	uint16_t pktlen;
	byte *packet; //Current packet received!
	FIFOBUFFER *packetserver_receivebuffer; //When receiving anything!
	byte *packetserver_transmitbuffer; //When sending a packet, this contains the currently built decoded data, which is already decoded!
	uint_32 packetserver_bytesleft;
	uint_32 packetserver_transmitlength; //How much has been built?
	uint_32 packetserver_transmitsize; //How much has been allocated so far, allocated in whole chunks?
	byte packetserver_transmitstate; //Transmit state for processing escaped values!
	char packetserver_username[256]; //Username(settings must match)
	char packetserver_password[256]; //Password(settings must match)
	char packetserver_protocol[256]; //Protocol(slip). Hangup when sent with username&password not matching setting.
	char packetserver_staticIP[4]; //Static IP to assign this user!
	char packetserver_staticIPstr[256]; //Static IP, string format
	byte packetserver_useStaticIP; //Use static IP?
	byte packetserver_slipprotocol; //Are we using the slip protocol?
	byte packetserver_slipprotocol_pppoe; //Are we using the PPPOE protocol instead of PPP?
	byte packetserver_stage; //Current login/service/packet(connected and authenticated state).
	word packetserver_stage_byte; //Byte of data within the current stage(else, use string length or connected stage(no position; in SLIP mode). 0xFFFF=Init new stage.
	byte packetserver_stage_byte_overflown; //Overflown?
	char packetserver_stage_str[4096]; //Buffer containing output data for a stage
	byte packetserver_credentials_invalid; //Marked invalid by username/password/service credentials?
	char packetserver_staticIPstr_information[268];
	DOUBLE packetserver_delay; //Delay for the packet server until doing something!
	uint_32 packetserver_packetpos; //Current pos of sending said packet!
	byte lastreceivedCRLFinput; //Last received input for CRLF detection!
	byte packetserver_packetack;
	sword connectionid; //The used connection!
	byte used; //Used client record?
	//Connection for PPP connections!
	MODEM_PACKETBUFFER pppoe_discovery_PADI; //PADI(Sent)!
	MODEM_PACKETBUFFER pppoe_discovery_PADO; //PADO(Received)!
	MODEM_PACKETBUFFER pppoe_discovery_PADR; //PADR(Sent)!
	MODEM_PACKETBUFFER pppoe_discovery_PADS; //PADS(Received)!
	MODEM_PACKETBUFFER pppoe_discovery_PADT; //PADT(Send final)!
	//Disconnect clears all of the above packets(frees them if set) when receiving/sending a PADT packet!
	byte pppoe_lastsentbytewasEND; //Last sent byte was END!
	byte pppoe_lastrecvbytewasEND; //Last received byte was END!
	//DHCP data
	MODEM_PACKETBUFFER DHCP_discoverypacket; //Discovery packet that's sent!
	MODEM_PACKETBUFFER DHCP_offerpacket; //Offer packet that's received!
	MODEM_PACKETBUFFER DHCP_requestpacket; //Request packet that's sent!
	MODEM_PACKETBUFFER DHCP_acknowledgepacket; //Acknowledge packet that's sent!
	MODEM_PACKETBUFFER DHCP_releasepacket; //Release packet that's sent!
	//PPP data
	byte PPP_packetstartsent; //Has a packet start been sent?
	byte PPP_packetreadyforsending; //Is the PPP packet ready to be sent to the client? 1 when containing data for the client, 0 otherwise. Ignored for non-PPP clients!
	byte PPP_packetpendingforsending; //Is the PPP packet pending processed for the client? 1 when pending to be processed for the client, 0 otherwise. Ignored for non-PPP clients!
	//Most PPP statuses and numbers are sets of two values: index 0 is the receiver(the client), index 1 is the sender(the server).
	//PPP CP packet processing
	byte PPP_headercompressed[2]; //Is the header compressed?
	byte PPP_protocolcompressed[2]; //Is the protocol compressed?
	word PPP_MRU[2]; //Pending MRU field for the request!
	MODEM_PACKETBUFFER ppp_response; //The PPP packet that's to be sent to the client!
	MODEM_PACKETBUFFER ppp_nakfields, ppp_nakfields_ipxcp, ppp_rejectfields, ppp_rejectfields_ipxcp; //The NAK and Reject packet that's pending to be sent!
	byte ppp_nakfields_identifier, ppp_nakfields_ipxcp_identifier, ppp_rejectfields_identifier, ppp_rejectfields_ipxcp_identifier; //The NAK and Reject packet identifier to be sent!
	byte ppp_LCPstatus[2]; //Current LCP status. 0=Init, 1=Open.

	//Some extra data for the server-client PPP LCP connection!
	TicksHolder ppp_serverLCPrequesttimer; //Server LCP request timer until a response is gotten!
	byte ppp_serverLCPstatus; //Server LCP status! 0=Not ready yet, 1=First requesting sent
	byte ppp_servercurrentLCPidentifier; //Current Server LCP identifier!
	byte ppp_serverLCPidentifier; //Server LCP identifier!
	byte ppp_serverLCP_haveMRU; //MRU trying?
	word ppp_serverLCP_pendingMRU; //MRU that's pending!
	//authentication protocol unsupported atm.
	//quality protocol unused
	byte ppp_serverLCP_haveMagicNumber; //Magic number trying?
	byte ppp_serverLCP_pendingMagicNumber[4]; //Magic number that's pending!
	byte ppp_serverLCP_haveProtocolFieldCompression; //Protocol Field Compression trying?
	byte ppp_serverLCP_haveAddressAndControlFieldCompression; //Address and Control Field Compression trying?
	byte ppp_serverLCP_haveAsyncControlCharacterMap; //ASync Control Character Map enabled?
	byte ppp_serverLCP_pendingASyncControlCharacterMap[4]; //ASync control character map that's pending!
	//Normal connection data
	byte ppp_protocolreject_count; //Protocol-Reject counter. From 0 onwards
	byte magic_number[2][4];
	byte have_magic_number[2];
	byte ppp_PAPstatus[2]; //0=Not authenticated, 1=Authenticated.
	byte ppp_IPXCPstatus[2]; //0=Not connected, 1=Connected
	byte ipxcp_networknumber[2][4];
	byte ipxcp_nodenumber[2][6];
	word ipxcp_routingprotocol[2];
	byte ipxcp_negotiationstatus; //Negotiation status for the IPXCP login. 0=Ready for new negotiation. 1=Negotiation request has been sent. 2=Negotation has been given a reply and to NAK, 3=Negotiation has succeeded.
	TicksHolder ipxcp_negotiationstatustimer; //Negotiation status timer for determining response time!
	uint_32 asynccontrolcharactermap[2]; //Async control character map, stored in little endian format!
} PacketServer_client;

PacketServer_client Packetserver_clients[0x100]; //Up to 100 clients!
word Packetserver_availableClients = 0; //How many clients are available?
word Packetserver_totalClients = 0; //How many clients are available?

//How much to delay before sending a message while authenticating?
#define PACKETSERVER_MESSAGE_DELAY 10000000.0
//How much to delay before DHCP timeout?
#define PACKETSERVER_DHCP_TIMEOUT 5000000000.0
//How much to delay before starting the SLIP service?
#define PACKETSERVER_SLIP_DELAY 300000000.0

//Different stages of the auth process:
//Ready stage 
//QueryUsername: Sending username request
#define PACKETSTAGE_REQUESTUSERNAME 1
//EnterUsername: Entering username
#define PACKETSTAGE_ENTERUSERNAME 2
//QueryPassword: Sending password request
#define PACKETSTAGE_REQUESTPASSWORD 3
//EnterPassword: Entering password
#define PACKETSTAGE_ENTERPASSWORD 4
//QueryProtocol: Sending protocol request
#define PACKETSTAGE_REQUESTPROTOCOL 5
//EnterProtocol: Entering protocol
#define PACKETSTAGE_ENTERPROTOCOL 6
//DHCP: DHCP obtaining or release phase.
#define PACKETSTAGE_DHCP 7
//Information: IP&MAC autoconfig. Terminates connection when earlier stages invalidate.
#define PACKETSTAGE_INFORMATION 8
//Ready: Sending ready and entering SLIP mode when finished.
#define PACKETSTAGE_READY 9
//SLIP: Delaying before starting the SLIP mode!
#define PACKETSTAGE_SLIPDELAY 10
//SLIP: Transferring SLIP data
#define PACKETSTAGE_PACKETS 11
//Initial packet stage without credentials
#define PACKETSTAGE_INIT PACKETSTAGE_REQUESTPROTOCOL
//Initial packet stage with credentials
#define PACKETSTAGE_INIT_PASSWORD PACKETSTAGE_REQUESTUSERNAME
//Packet stage initializing
#define PACKETSTAGE_INITIALIZING 0xFFFF

//SLIP reserved values
//End of frame byte!
#define SLIP_END 0xC0
//Escape byte!
#define SLIP_ESC 0xDB
//END is being send(send after ESC)
#define SLIP_ESC_END 0xDC
//ESC is being send(send after ESC)
#define SLIP_ESC_ESC 0xDD

//PPP reserved values
//End of frame byte
#define PPP_END 0x7E
//Escape
#define PPP_ESC 0x7D
//Escaped value encoding and decoding
#define PPP_ENCODEESC(val) (val^0x20)
#define PPP_DECODEESC(val) (val^0x20)

//Define below to encode/decode the PPP packets sent/received from the user using the PPP_ESC values
#define PPPOE_ENCODEDECODE 0

#ifdef PACKETSERVER_ENABLED
struct netstruct { //Supported, thus use!
#else
struct {
#endif
	uint16_t pktlen;
	byte *packet; //Current packet received!
} net;

#include "headers/packed.h"
typedef union PACKED
{
	struct
	{
		byte dst[6]; //Destination MAC!
		byte src[6]; //Source MAC!
		word type; //What kind of packet!
	};
	byte data[14]; //The data!
} ETHERNETHEADER;
#include "headers/endpacked.h"

//Normal modem operations!
#define MODEM_BUFFERSIZE 256

//Server polling speed
#define MODEM_SERVERPOLLFREQUENCY 1000
//Data tranfer frequency of transferring data
#define MODEM_DATATRANSFERFREQUENCY 57600
//Data transfer frequency of tranferring data, in the numeric result code of the connection numeric result code! Must match the MODEM_DATATRANSFERFREQUENCY
#define MODEM_DATATRANSFERFREQUENCY_NR 18
//Command completion timeout after receiving a carriage return during a command!
#define MODEM_COMMANDCOMPLETIONTIMEOUT (DOUBLE)((1000000000.0/57600.0)*5760.0)

struct
{
	byte supported; //Are we supported?
	FIFOBUFFER *inputbuffer; //The input buffer!
	FIFOBUFFER *inputdatabuffer[0x100]; //The input buffer, data mode only!
	FIFOBUFFER *outputbuffer[0x100]; //The output buffer!
	byte datamode; //1=Data mode, 0=Command mode!
	byte connected; //Are we connected?
	word connectionport; //What port to connect to by default?
	byte previousATCommand[256]; //Copy of the command for use with "A/" command!
	byte ATcommand[256]; //AT command in uppercase when started!
	byte ATcommandoriginalcase[256]; //AT command in original unmodified case!
	word ATcommandsize; //The amount of data sent!
	byte escaping; //Are we trying to escape?
	DOUBLE timer; //A timer for detecting timeout!
	DOUBLE ringtimer; //Ringing timer!
	DOUBLE serverpolltimer; //Network connection request timer!
	DOUBLE networkdatatimer; //Network connection request timer!

	DOUBLE serverpolltick; //How long it takes!
	DOUBLE networkpolltick;
	DOUBLE detectiontimer[2]; //For autodetection!
	DOUBLE RTSlineDelay; //Delay line on the CTS!
	DOUBLE effectiveRTSlineDelay; //Effective CTS line delay to use!
	DOUBLE DTRlineDelay; //Delay line on the DSR!
	DOUBLE effectiveDTRlineDelay; //Effective DSR line delay to use!

	byte TxDisMark; //Is TxD currently in mark state?
	byte TxDisBreak; //Is TxD currently in the break state?

	//Various parameters used!
	byte communicationstandard; //What communication standard! B command!
	byte echomode; //Echo everything back to use user? E command!
	byte offhook; //1: Off hook(disconnected), 2=Off hook(connected), otherwise on-hook(disconnected)! H command!
	byte verbosemode; //Verbose mode: 0=Numeric result codes, 1=Text result codes, 2=Quiet mode(no response). Bit 0=V command, Bits 1-2=Q command
	byte speakervolume; //Speaker volume! L command!
	byte speakercontrol; //0=Always off, 1=On until carrier detected, 2=Always on, 3=On only while answering! M command!
	byte callprogressmethod; //Call progress method! X command!
	byte lastnumber[256]; //Last-dialed number!
	byte currentregister; //What register is selected?
	byte registers[256]; //All possible registers!
	byte flowcontrol; //&K command! See below for an explanation!
	/*
	0=Blind dial and no busy detect. CONNECT message when established.
	1=Blind dial and no busy detect. Connection speed in BPS added to CONNECT string.
	2=Dial tone detection, but no busy detection. Connection speed in BPS added to the CONNECT string.
	3=Blind dial, but busy detection. Connection speed in BPS appended to the CONNECT string.
	4=Dial tone detection and busy tone detection. Connection speed in BPS appended to the CONNECT string.
	*/
	byte communicationsmode; //Communications mode, default=5! &Q command!

	//Active status emulated for the modem!
	byte ringing; //Are we ringing?
	byte DTROffResponse; //Default: full reset! &D command!
	byte DSRisConnectionEstablished; //Default: assert high always! &S command!
	byte DCDisCarrier; //&C command!
	byte CTSAlwaysActive; //Default: always active! &R command!

	//Various characters that can be sent, set by the modem's respective registers!
	byte escapecharacter;
	byte carriagereturncharacter;
	byte linefeedcharacter;
	byte backspacecharacter;
	DOUBLE escapecodeguardtime;

	//Allocated UART port
	byte port; //What port are we allocated to?
	
	//Line status for the different modem lines!
	byte canrecvdata; //Can we start receiving data to the UART?
	byte linechanges; //For detecting line changes!
	byte outputline; //Raw line that's output!
	byte outputlinechanges; //For detecting line changes!
	byte effectiveline; //Effective line to actually use!
	byte effectivelinechanges; //For detecting line changes!

	//What is our connection ID, if we're connected?
	sword connectionid; //Normal connection ID for the internal modem!

	//Command completion status!
	byte wascommandcompletionecho; //Was command completion with echo!
	DOUBLE wascommandcompletionechoTimeout; //Timeout for execution anyways!
	byte passthroughlinestatusdirty; //Passthrough mode line status dirty? Bit 0=DTR, bit 1=RTS, bit 2=Break
	byte passthroughescaped; //Was the last byte escaped?
	byte passthroughlines; //The actual lines that were received in passthrough mode!
	byte breakPending; //Is a break pending to be received on the receiver of the connection?
} modem;

byte readIPnumber(char **x, byte *number); //Prototype!

void initPacketServerClients()
{
	Packetserver_availableClients = Packetserver_totalClients = NUMITEMS(Packetserver_clients); //How many available clients!
}

//Supported and enabled the packet setver?
#if defined(PACKETSERVER_ENABLED)
#ifndef _WIN32
#ifndef IS_LINUX
#ifndef NOPCAP
#define PCAP_OPENFLAG_PROMISCUOUS 1
#endif
#endif
#endif

byte pcap_loaded = 0; //Is WinPCap loaded?
byte dummy;
int_64 ethif = 0;
uint8_t pcap_enabled = 0;
byte pcap_receiverstate = 0;
uint8_t dopktrecv = 0;
uint16_t rcvseg, rcvoff, hdrlen, handpkt;

#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
pcap_if_t *alldevs;
pcap_if_t *d;
pcap_t *adhandle;
const u_char *pktdata;
struct pcap_pkthdr *hdr;
int_64 inum;
uint16_t curhandle = 0;
char errbuf[PCAP_ERRBUF_SIZE];
#endif
uint8_t maclocal_default[6] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37 }; //The MAC address of the modem we're emulating!
byte pcap_verbose = 0;

#ifdef WPCAP_WASNTDEFINED
#ifdef IS_WINDOWS
byte LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		return FALSE;
	}
	return TRUE;
}
#endif
#endif

void initPcap() {
	memset(&net,0,sizeof(net)); //Init!
	int i=0;
	char *p;
	byte IPnumbers[4];

#ifdef WPCAP_WASNTDEFINED
#ifdef IS_WINDOWS
	dummy = LoadNpcapDlls(); //Try and load the npcap DLLs if present!
#endif
#endif

#ifdef _WIN32
	pcap_loaded = LoadPcapLibrary(); //Load the PCap library that's to be used!
#else
#if defined(IS_LINUX) && !defined(NOPCAP)
	pcap_loaded = 1; //pcap is always assumed loaded on Linux!
#endif
#endif

	/*

	Custom by superfury

	*/
	memset(&Packetserver_clients, 0, sizeof(Packetserver_clients)); //Initialize the clients!
	initPacketServerClients();
	PacketServer_running = 0; //We're not using the packet server emulation, enable normal modem(we don't connect to other systems ourselves)!

#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	if ((BIOS_Settings.ethernetserver_settings.ethernetcard==-1) || (BIOS_Settings.ethernetserver_settings.ethernetcard<0)) //No ethernet card to emulate?
	{
		return; //Disable ethernet emulation!
	}
	ethif = BIOS_Settings.ethernetserver_settings.ethernetcard; //What ethernet card to use?
#endif

	//Load MAC address!
	int values[6];

#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	if( 6 == sscanf( BIOS_Settings.ethernetserver_settings.MACaddress, "%02x:%02x:%02x:%02x:%02x:%02x%*c",
		&values[0], &values[1], &values[2],
		&values[3], &values[4], &values[5] ) ) //Found a MAC address to emulate?
	{
		/* convert to uint8_t */
		for( i = 0; i < 6; ++i )
			maclocal[i] = (uint8_t) values[i]; //MAC address parts!
	}
	else
	{
		memcpy(&maclocal,&maclocal_default,sizeof(maclocal)); //Copy the default MAC address to use!
	}
	if( 6 == sscanf( BIOS_Settings.ethernetserver_settings.gatewayMACaddress, "%02x:%02x:%02x:%02x:%02x:%02x%*c",
		&values[0], &values[1], &values[2],
		&values[3], &values[4], &values[5] ) ) //Found a MAC address to emulate?
	{
		/* convert to uint8_t */
		for( i = 0; i < 6; ++i )
			packetserver_gatewayMAC[i] = (uint8_t) values[i]; //MAC address parts!
	}
	else
	{
		memset(&packetserver_gatewayMAC,0,sizeof(packetserver_gatewayMAC)); //Nothing!
		//We don't have the required addresses! Log and abort!
		dolog("ethernetcard", "Gateway MAC address is required on this platform! Aborting server installation!");
		return; //Disable ethernet emulation!
	}
#endif

	memcpy(&packetserver_sourceMAC,&maclocal,sizeof(packetserver_sourceMAC)); //Load sender MAC to become active!

	memset(&packetserver_defaultstaticIPstr, 0, sizeof(packetserver_defaultstaticIPstr));
	memset(&packetserver_defaultstaticIP, 0, sizeof(packetserver_defaultstaticIP));
	packetserver_usedefaultStaticIP = 0; //Default to unused!

#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	if (safestrlen(&BIOS_Settings.ethernetserver_settings.users[0].IPaddress[0], 256) >= 12) //Valid length to convert IP addresses?
	{
		p = &BIOS_Settings.ethernetserver_settings.users[0].IPaddress[0]; //For scanning the IP!
		if (readIPnumber(&p, &IPnumbers[0]))
		{
			if (readIPnumber(&p, &IPnumbers[1]))
			{
				if (readIPnumber(&p, &IPnumbers[2]))
				{
					if (readIPnumber(&p, &IPnumbers[3]))
					{
						if (*p == '\0') //EOS?
						{
							//Automatic port?
							snprintf(packetserver_defaultstaticIPstr, sizeof(packetserver_defaultstaticIPstr), "%u.%u.%u.%u", IPnumbers[0], IPnumbers[1], IPnumbers[2], IPnumbers[3]); //Formulate the address!
							memcpy(&packetserver_defaultstaticIP, &IPnumbers, 4); //Set read IP!
							packetserver_usedefaultStaticIP = 1; //Static IP set!
						}
					}
				}
			}
		}
	}
#else
	memset(&maclocal, 0, sizeof(maclocal));
	memset(&packetserver_gatewayMAC, 0, sizeof(packetserver_gatewayMAC));
#endif

	dolog("ethernetcard","Receiver MAC address: %02x:%02x:%02x:%02x:%02x:%02x",maclocal[0],maclocal[1],maclocal[2],maclocal[3],maclocal[4],maclocal[5]);
	dolog("ethernetcard","Gateway MAC Address: %02x:%02x:%02x:%02x:%02x:%02x",packetserver_gatewayMAC[0],packetserver_gatewayMAC[1],packetserver_gatewayMAC[2],packetserver_gatewayMAC[3],packetserver_gatewayMAC[4],packetserver_gatewayMAC[5]); //Log loaded address!
	if (packetserver_usedefaultStaticIP) //Static IP configured?
	{
		dolog("ethernetcard","Static IP configured: %s(%02x%02x%02x%02x)",packetserver_defaultstaticIPstr,packetserver_defaultstaticIP[0],packetserver_defaultstaticIP[1],packetserver_defaultstaticIP[2],packetserver_defaultstaticIP[3]); //Log it!
	}

	for (i = 0; i < NUMITEMS(Packetserver_clients); ++i) //Initialize client data!
	{
		Packetserver_clients[i].packetserver_receivebuffer = allocfifobuffer(3, 0); //Simple receive buffer, the size of a packet byte(when encoded) to be able to buffer any packet(since any byte can be doubled)! This is 2 bytes required for SLIP, while 3 bytes for PPP(for the extra PPP_END character at the start of a first packet)
		Packetserver_clients[i].packetserver_transmitlength = 0; //We're at the start of this buffer, nothing is sent yet!
	}

	/*

	End of custom!

	*/

	i = 0; //Init!

	if (!pcap_loaded) //PCap isn't loaded?
	{
		dolog("ethernetcard", "The pcap interface and packet server is disabled because the required libraries aren't installed!");
		pcap_enabled = 0;
		pcap_receiverstate = 0; //Packet receiver/filter state: ready to receive a packet!
		PacketServer_running = 0; //We're using the packet server emulation, disable normal modem(we don't connect to other systems ourselves)!
		return; //Abort!
	}

	dolog("ethernetcard","Obtaining NIC list via libpcap...");

#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	/* Retrieve the device list from the local machine */
#if defined(_WIN32)
#ifdef WPCAP
	//Winpcap version!
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
#else
	if (pcap_findalldevs (&alldevs, errbuf))
#endif
#else
	if (pcap_findalldevs (&alldevs, errbuf))
#endif
		{
			dolog("ethernetcard","Error in pcap_findalldevs_ex: %s", errbuf);
			exit (1);
		}

	/* Print the list */
	for (d= alldevs; d != NULL; d= d->next) {
			i++;
			if (ethif==0) {
					dolog("ethernetcard","%d. %s", i, d->name);
					if (d->description) {
							dolog("ethernetcard"," (%s)", d->description);
						}
					else {
							dolog("ethernetcard"," (No description available)");
						}
				}
		}

	if (i == 0) {
			dolog("ethernetcard","No interfaces found! Make sure WinPcap is installed.");
			return;
		}

	if (ethif==0) exit (0); //Failed: no ethernet card to use: only performing detection!
	else inum = ethif;
	dolog("ethernetcard","Using network interface %u.", ethif);


	if (inum < 1 || inum > i) {
			dolog("ethernetcard","Interface number out of range.");
			/* Free the device list */
			pcap_freealldevs (alldevs);
			return;
		}

	/* Jump to the selected adapter */
	for (d=alldevs, i=0; ((i< inum-1) && d) ; d=d->next, i++);

	/* Open the device */
#ifdef _WIN32
#ifdef WPCAP
	//Winpcap version!
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, -1, NULL, errbuf)) == NULL)
#else
	if ((adhandle = pcap_open_live(d->name, 65535, 1, -1, NULL)) == NULL)
#endif
#else
	if ( (adhandle= pcap_open_live (d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, -1, errbuf) ) == NULL)
#endif
		{
			dolog("ethernetcard","Unable to open the adapter. %s is not supported by WinPcap. Reason: %s", d->name, errbuf);
			/* Free the device list */
			pcap_freealldevs (alldevs);
			exit(1);
			return;
		}

	dolog("ethernetcard","Ethernet bridge on %s (%s)...", d->name, d->description?d->description:"No description available");

	if (pcap_datalink(adhandle)!=DLT_EN10MB) //Invalid link layer?
	{
		dolog("ethernetcard","Ethernet card unsupported: Ethernet card is required! %s is unsupported!", d->description ? d->description : "No description available");
		/* Free the device list */
		pcap_freealldevs (alldevs);
		pcap_close(adhandle); //Close the handle!
		return;		
	}

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs (alldevs);
	pcap_enabled = 1;
	pcap_receiverstate = 0; //Packet receiver/filter state: ready to receive a packet!
#endif
	PacketServer_running = 1; //We're using the packet server emulation, disable normal modem(we don't connect to other systems ourselves)!
}

void fetchpackets_pcap() { //Handle any packets to process!
#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	//Filter parameters to apply!
	ETHERNETHEADER ethernetheader; //The header to inspect!
	uint_32 detselfrelpos;
	uint_32 detselfdataleft;
	byte IP_useIHL;

	if (pcap_enabled) //Enabled?
	{
		//Check for new packets arriving and filter them as needed!
		if (pcap_receiverstate == 0) //Ready to receive a new packet?
		{
		invalidpacket_receivefilter:
			if (pcap_next_ex(adhandle, &hdr, &pktdata) <= 0) return; //Nothing valid to process?
			if (hdr->len == 0) goto invalidpacket_receivefilter; //Try again on invalid 

			//Packet received!
			memcpy(&ethernetheader.data, &pktdata[0], sizeof(ethernetheader.data)); //Copy to the client buffer for inspection!
			//Check for the packet type first! Don't receive anything that is our unsupported (the connected client)!
			if (ethernetheader.type != SDL_SwapBE16(0x0800)) //Not IP packet?
			{
				if (ethernetheader.type != SDL_SwapBE16(0x8863)) //Are we not a discovery packet?
				{
					if (ethernetheader.type != SDL_SwapBE16(0x8864)) //Not Receiving uses normal PPP packets to transfer/receive on the receiver line only!
					{
						if (ethernetheader.type != SDL_SwapBE16(0x8864)) //Not Receiving uses normal PPP packets to transfer/receive on the receiver line only!
						{
							if (ethernetheader.type != SDL_SwapBE16(0x8137)) //Not an IPX packet!
							{
								if (ethernetheader.type != SDL_SwapBE16(0x0806)) //Not ARP?
								{
									//This is an unsupported packet type discard it fully and don't look at it anymore!
									//Discard the received packet, so nobody else handles it too!
									goto invalidpacket_receivefilter; //Ignore this packet and check for more!
								}
							}
						}
					}
				}
			}

			//Check for the client first! Don't receive anything that is our own traffic (the connected client)!
			if (ethernetheader.type == SDL_SwapBE16(0x0800)) //IP packet?
			{
				//Check for TCP packet in the IP packet!
				detselfrelpos = sizeof(ethernetheader.data); //Start of the IP packet!
				detselfdataleft = hdr->len - detselfrelpos; //Data left to parse as subpackets!
				if (detselfdataleft >= 20) //Enough data left to parse?
				{
					if (pktdata[detselfrelpos + 9] == 6) //TCP protocol?
					{
						if ((memcmp(&pktdata[detselfrelpos + 0xC], &packetserver_defaultstaticIP[0], 4) == 0) || (memcmp(&pktdata[detselfrelpos + 0x10], &packetserver_defaultstaticIP[0], 4) == 0)) //Our  own IP in source or destination?
						{
							IP_useIHL = (((pktdata[detselfrelpos] & 0xF0) >> 4) << 5); //IHL field, in bytes!
							if ((detselfdataleft > IP_useIHL) && (IP_useIHL)) //Enough left for the subpacket?
							{
								detselfrelpos += IP_useIHL; //TCP Data position!
								detselfdataleft -= IP_useIHL; //How much data if left!
								//Now we're at the start of the TCP packet!
								if (detselfdataleft >= 4) //Valid to filter the port?
								{
									if ((SDL_SwapBE16(*((word*)&pktdata[detselfrelpos])) == modem.connectionport) || //Own source port?
										(SDL_SwapBE16(*((word*)&pktdata[detselfrelpos + 2])) == modem.connectionport) //Own destination port?
										)
									{
										//Discard the received packet, so nobody else handles it too!
										goto invalidpacket_receivefilter; //Ignore this packet and check for more!
									}
								}
							}
						}
					}
				}
			}
			else if (ethernetheader.type == SDL_SwapBE16(0x0806)) //ARP?
			{
				if ((hdr->len - sizeof(ethernetheader.data))!=28) //Wrong length?
				{
					goto invalidpacket_receivefilter; //Ignore this packet and check for more!
				}
			}

			//Packet ready to receive!
			pcap_receiverstate = 1; //Packet is loaded and ready to parse by the receiver algorithm!
		}

		if ((net.packet == NULL) && (pcap_receiverstate==1)) //Can we receive anything and receiver is loaded?
		{
			//Packet acnowledged for clients to receive!
			net.packet = zalloc(hdr->len, "MODEM_PACKET", NULL);
			if (net.packet) //Allocated?
			{
				memcpy(net.packet, &pktdata[0], hdr->len);
				net.pktlen = (uint16_t)hdr->len;
				if (pcap_verbose) {
					dolog("ethernetcard", "Received packet of %u bytes.", net.pktlen);
				}
				//Packet received!
				pcap_receiverstate = 0; //Start scanning for incoming packets again, since the receiver is cleared again!
				return;
			}
		}
	}
#endif
}

void sendpkt_pcap (uint8_t *src, uint16_t len) {
#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	if (pcap_enabled) //Enabled?
	{
		pcap_sendpacket (adhandle, src, len);
	}
#endif
}

void termPcap()
{
	if (net.packet)
	{
		freez((void **)&net.packet,net.pktlen,"MODEM_PACKET"); //Cleanup!
	}
	word client;
	for (client = 0; client < NUMITEMS(Packetserver_clients); ++client) //Process all clients!
	{
		if (Packetserver_clients[client].packet)
		{
			freez((void **)&Packetserver_clients[client].packet, Packetserver_clients[client].pktlen, "SERVER_PACKET"); //Cleanup!
		}
		if (Packetserver_clients[client].packetserver_receivebuffer)
		{
			free_fifobuffer(&Packetserver_clients[client].packetserver_receivebuffer); //Cleanup!
		}
		if (Packetserver_clients[client].packetserver_transmitbuffer && Packetserver_clients[client].packetserver_transmitsize) //Gotten a send buffer allocated?
		{
			freez((void **)&Packetserver_clients[client].packetserver_transmitbuffer, Packetserver_clients[client].packetserver_transmitsize, "MODEM_SENDPACKET"); //Clear the transmit buffer!
			if (Packetserver_clients[client].packetserver_transmitbuffer == NULL) Packetserver_clients[client].packetserver_transmitsize = 0; //Nothing allocated anymore!
		}
	}
#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	if (pcap_enabled)
	{
		pcap_close(adhandle); //Close the capture/transmit device!
	}
#endif
}
#else
//Not supported?
void initPcap() //Unsupported!
{
	memset(&net,0,sizeof(net)); //Init!
}
void sendpkt_pcap (uint8_t *src, uint16_t len)
{
}
void fetchpackets_pcap() //Handle any packets to process!
{
}
void termPcap()
{
}
#endif

sword allocPacketserver_client()
{
	sword i;
	if (Packetserver_availableClients == 0) return -1; //None available!
	--Packetserver_availableClients; //One taken!
	for (i = 0; i < NUMITEMS(Packetserver_clients); ++i) //Find an unused one!
	{
		if (Packetserver_clients[i].used) continue; //Take unused only!
		if (!Packetserver_clients[i].packetserver_receivebuffer) continue; //Required to receive properly!
		Packetserver_clients[i].used = 1; //We're used now!
		return i; //Give the ID!
	}
	++Packetserver_availableClients; //Couldn't allocate, discard!
	return -1; //Failed to allocate!
}

byte freePacketserver_client(sword client)
{
	if (client >= NUMITEMS(Packetserver_clients)) return 0; //Failure: invalid client!
	if (Packetserver_clients[client].used) //Used?
	{
		Packetserver_clients[client].used = 0; //Not used anymore!
		++Packetserver_availableClients; //One client became available!
		return 1; //Success!
	}
	return 0; //Failure!
}

void packetServerFreePacketBufferQueue(MODEM_PACKETBUFFER* buffer); //Prototype for freeing of DHCP when not connected!

void normalFreeDHCP(sword connectedclient)
{
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_discoverypacket); //Free the old one first, if present!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_offerpacket); //Free the old one first, if present!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_requestpacket); //Free the old one first, if present!
}

void terminatePacketServer(sword client) //Cleanup the packet server after being disconnected!
{
	fifobuffer_clear(Packetserver_clients[client].packetserver_receivebuffer); //Clear the receive buffer!
	freez((void **)&Packetserver_clients[client].packetserver_transmitbuffer,Packetserver_clients[client].packetserver_transmitsize,"MODEM_SENDPACKET"); //Clear the transmit buffer!
	if (Packetserver_clients[client].packetserver_transmitbuffer==NULL) Packetserver_clients[client].packetserver_transmitsize = 0; //Clear!
}

void PacketServer_startNextStage(sword connectedclient, byte stage)
{
	Packetserver_clients[connectedclient].packetserver_stage_byte = PACKETSTAGE_INITIALIZING; //Prepare for next step!
	Packetserver_clients[connectedclient].packetserver_stage = stage; //The specified stage that's starting!
}

void initPacketServer(sword client) //Initialize the packet server for use when connected to!
{
#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	word c;
#endif
	terminatePacketServer(client); //First, make sure we're terminated properly!
	Packetserver_clients[client].packetserver_transmitsize = 1024; //Initialize transmit buffer!
	Packetserver_clients[client].packetserver_transmitbuffer = zalloc(Packetserver_clients[client].packetserver_transmitsize,"MODEM_SENDPACKET",NULL); //Initial transmit buffer!
	Packetserver_clients[client].packetserver_transmitlength = 0; //Nothing buffered yet!
	Packetserver_clients[client].packetserver_transmitstate = 0; //Initialize transmitter state to the default state!
	Packetserver_clients[client].packetserver_stage = PACKETSTAGE_INIT; //Initial state when connected.
#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
	for (c=0;c<NUMITEMS(BIOS_Settings.ethernetserver_settings.users);++c)
	{
		if (BIOS_Settings.ethernetserver_settings.users[c].username[0]&&BIOS_Settings.ethernetserver_settings.users[c].password[0]) //Gotten credentials?
		{
			Packetserver_clients[client].packetserver_stage = PACKETSTAGE_INIT_PASSWORD; //Initial state when connected: ask for credentials too.
			break;
		}
	}
#endif
	Packetserver_clients[client].packetserver_stage_byte = PACKETSTAGE_INITIALIZING; //Reset stage byte: uninitialized!
	if (Packetserver_clients[client].packet)
	{
		freez((void **)&Packetserver_clients[client].packet, Packetserver_clients[client].pktlen, "SERVER_PACKET"); //Release the buffered packet: we're a new client!
		Packetserver_clients[client].packet = NULL; //No packet anymore!
	}
	Packetserver_clients[client].packetserver_packetpos = 0; //No packet buffered anymore! New connections must read a new packet!
	Packetserver_clients[client].packetserver_packetack = 0; //Not acnowledged yet!
	fifobuffer_clear(modem.inputdatabuffer[client]); //Nothing is received yet!
	fifobuffer_clear(modem.outputbuffer[client]); //Nothing is sent yet!
	Packetserver_clients[client].packetserver_slipprotocol = 0; //Initialize the protocol to the default value, which is unused!
	Packetserver_clients[client].lastreceivedCRLFinput = 0; //Reset last received input to none of CR and LF!
}

byte packetserver_authenticate(sword client)
{
#ifdef PACKETSERVER_ENABLED
#ifndef NOPCAP
	byte IPnumbers[4];
	word c;
	char *p;
#endif
#endif
	if ((strcmp(Packetserver_clients[client].packetserver_protocol, "slip") == 0) || (strcmp(Packetserver_clients[client].packetserver_protocol, "ethernetslip") == 0) || (strcmp(Packetserver_clients[client].packetserver_protocol, "ipxslip") == 0) || (strcmp(Packetserver_clients[client].packetserver_protocol, "ppp") == 0) || (strcmp(Packetserver_clients[client].packetserver_protocol, "pppoe") == 0)) //Valid protocol?
	{
#ifdef PACKETSERVER_ENABLED
#ifndef NOPCAP
		if (!(BIOS_Settings.ethernetserver_settings.users[0].username[0] && BIOS_Settings.ethernetserver_settings.users[0].password[0])) //Gotten no default credentials?
		{
			safestrcpy(Packetserver_clients[client].packetserver_staticIPstr, sizeof(Packetserver_clients[client].packetserver_staticIPstr), packetserver_defaultstaticIPstr); //Default!
			memcpy(&Packetserver_clients[client].packetserver_staticIP, &packetserver_defaultstaticIP, 4); //Set read IP!
			Packetserver_clients[client].packetserver_useStaticIP = packetserver_usedefaultStaticIP; //Static IP set!
			return 1; //Always valid: no credentials required!
		}
		else
		{
			for (c = 0; c < NUMITEMS(BIOS_Settings.ethernetserver_settings.users); ++c) //Check all users!
			{
				if (!(BIOS_Settings.ethernetserver_settings.users[c].username[c] && BIOS_Settings.ethernetserver_settings.users[c].password[c])) //Gotten no credentials?
					continue;
				if (!(strcmp(BIOS_Settings.ethernetserver_settings.users[c].username, Packetserver_clients[client].packetserver_username) || strcmp(BIOS_Settings.ethernetserver_settings.users[c].password, Packetserver_clients[client].packetserver_password))) //Gotten no credentials?
				{
					//Determine the IP address!
					memcpy(&Packetserver_clients[client].packetserver_staticIP, &packetserver_defaultstaticIP, sizeof(Packetserver_clients[client].packetserver_staticIP)); //Use the default IP!
					safestrcpy(Packetserver_clients[client].packetserver_staticIPstr, sizeof(Packetserver_clients[client].packetserver_staticIPstr), packetserver_defaultstaticIPstr); //Formulate the address!
					Packetserver_clients[client].packetserver_useStaticIP = 0; //Default: not detected!
					if (safestrlen(&BIOS_Settings.ethernetserver_settings.users[c].IPaddress[0], 256) >= 12) //Valid length to convert IP addresses?
					{
						p = &BIOS_Settings.ethernetserver_settings.users[c].IPaddress[0]; //For scanning the IP!

						if (readIPnumber(&p, &IPnumbers[0]))
						{
							if (readIPnumber(&p, &IPnumbers[1]))
							{
								if (readIPnumber(&p, &IPnumbers[2]))
								{
									if (readIPnumber(&p, &IPnumbers[3]))
									{
										if (*p == '\0') //EOS?
										{
											//Automatic port?
											snprintf(Packetserver_clients[client].packetserver_staticIPstr, sizeof(Packetserver_clients[client].packetserver_staticIPstr), "%u.%u.%u.%u", IPnumbers[0], IPnumbers[1], IPnumbers[2], IPnumbers[3]); //Formulate the address!
											memcpy(&Packetserver_clients[client].packetserver_staticIP, &IPnumbers, 4); //Set read IP!
											Packetserver_clients[client].packetserver_useStaticIP = 1; //Static IP set!
										}
									}
								}
							}
						}
					}
					else if (safestrlen(&BIOS_Settings.ethernetserver_settings.users[c].IPaddress[0], 256) == 4) //Might be DHCP?
					{
						if ((strcmp(BIOS_Settings.ethernetserver_settings.users[c].IPaddress, "DHCP") == 0) || (strcmp(BIOS_Settings.ethernetserver_settings.users[0].IPaddress, "DHCP") == 0)) //DHCP used for this user or all users?
						{
							//Packetserver_clients[client].packetserver_useStaticIP = 2; //DHCP requested instead of static IP! Not used yet!
						}
					}
					if (!Packetserver_clients[client].packetserver_useStaticIP) //Not specified? Use default!
					{
						safestrcpy(Packetserver_clients[client].packetserver_staticIPstr, sizeof(Packetserver_clients[client].packetserver_staticIPstr), packetserver_defaultstaticIPstr); //Default!
						memcpy(&Packetserver_clients[client].packetserver_staticIP, &packetserver_defaultstaticIP, 4); //Set read IP!
						Packetserver_clients[client].packetserver_useStaticIP = packetserver_usedefaultStaticIP; //Static IP set!
					}
					return 1; //Valid credentials!
				}
			}
		}
#else
		return 1; //Valid credentials!
#endif
#endif
	}
	return 0; //Invalid credentials!
}

byte ATresultsString[6][256] = {"ERROR","OK","CONNECT","RING","NO DIALTONE","NO CARRIER"}; //All possible results!
byte ATresultsCode[6] = {4,0,1,2,6,3}; //Code version!
#define MODEMRESULT_ERROR 0
#define MODEMRESULT_OK 1
#define MODEMRESULT_CONNECT 2
#define MODEMRESULT_RING 3
#define MODEMRESULT_NODIALTONE 4
#define MODEMRESULT_NOCARRIER 5

//usecarriagereturn: bit0=before, bit1=after, bit2=use linefeed
void modem_responseString(byte *s, byte usecarriagereturn)
{
	word i, lengthtosend;
	lengthtosend = (word)safestrlen((char *)s,256); //How long to send!
	if (modem.supported >= 2) return; //No command interface? Then no results!
	if (usecarriagereturn&1)
	{
		writefifobuffer(modem.inputbuffer,modem.carriagereturncharacter); //Termination character!
		if (usecarriagereturn&4) writefifobuffer(modem.inputbuffer,modem.linefeedcharacter); //Termination character!
	}
	for (i=0;i<lengthtosend;) //Process all data to send!
	{
		writefifobuffer(modem.inputbuffer,s[i++]); //Send the character!
	}
	if (usecarriagereturn&2)
	{
		writefifobuffer(modem.inputbuffer,modem.carriagereturncharacter); //Termination character!
		if (usecarriagereturn&4) writefifobuffer(modem.inputbuffer,modem.linefeedcharacter); //Termination character!
	}
}
void modem_nrcpy(char *s, word size, word nr)
{
	memset(s,0,size);
	snprintf(s,size,"%u",nr); //Convert to string!
}
char connectionspeed[256]; //Connection speed!
void modem_responseResult(byte result) //What result to give!
{
	byte s[256];
	if (result>=MIN(NUMITEMS(ATresultsString),NUMITEMS(ATresultsCode))) //Out of range of results to give?
	{
		result = MODEMRESULT_ERROR; //Error!
	}
	if ((modem.verbosemode & 6)==2) //All off?
	{
		return; //Quiet mode? No response messages!
	}
	if ((modem.verbosemode & 6) == 4) //No ring and connect/carrier?
	{
		if ((result == MODEMRESULT_RING) || (result == MODEMRESULT_CONNECT) || (result == MODEMRESULT_NOCARRIER)) //Don't send these when sending results?
		{
			return; //Don't send these results!
		}
	}

	//Now, the results can have different formats:
	/*
	- V0 information text: text<CR><LF>
	- V0 numeric code: code<CR>
	- V1 information text: <CR><LF>text<CR><LF>
	- V1 numeric code: <CR><LF>verbose code<CR><LF>
	*/

	if (modem.verbosemode&1) //Text format result?
	{
		modem_responseString(&ATresultsString[result][0],(((result!=MODEMRESULT_CONNECT) || (modem.callprogressmethod==0))?3:1)|4); //Send the string to the user!
		if ((result == MODEMRESULT_CONNECT) && modem.callprogressmethod) //Add speed as well?
		{
			memset(&connectionspeed,0,sizeof(connectionspeed)); //Init!
			safestrcpy(connectionspeed, sizeof(connectionspeed), " "); //Init!
			safescatnprintf(connectionspeed, sizeof(connectionspeed), "%u", (uint_32)MODEM_DATATRANSFERFREQUENCY); //Add the data transfer frequency!
			modem_responseString((byte *)&connectionspeed[0], (2 | 4)); //End the command properly with a speed indication in bps!
		}
	}
	else //Numeric format result? This is V0 beign active! So just CR after!
	{
		if ((result == MODEMRESULT_CONNECT) && modem.callprogressmethod) //Add speed as well?
		{
			modem_nrcpy((char*)&s[0], sizeof(s), MODEM_DATATRANSFERFREQUENCY_NR); //Report 57600!
		}
		else //Normal result code?
		{
			modem_nrcpy((char*)&s[0], sizeof(s), ATresultsCode[result]);
		}
		modem_responseString(&s[0],((2)));
	}
}

void modem_responseNumber(byte x)
{
	char s[256];
	/*
	- V0 information text: text<CR><LF>
	-> V0 numeric code: code<CR>
	- V1 information text: <CR><LF>text<CR><LF>
	-> V1 numeric code: <CR><LF>verbose code<CR><LF>
	*/
	if (modem.verbosemode&1) //Text format result?
	{
		memset(&s,0,sizeof(s));
		snprintf(s,sizeof(s),"%u",x); //Convert to a string!
		modem_responseString((byte *)&s,(1|2|4)); //Send the string to the user! CRLF before and after!
	}
	else
	{
		modem_nrcpy((char*)&s[0], sizeof(s), x);
		modem_responseString((byte *)&s[0], (2)); //Send the numeric result to the user! CR after!
	}
}

byte modem_sendData(byte value) //Send data to the connected device!
{
	//Handle sent data!
	if (PacketServer_running) return 0; //Not OK to send data this way!
	if (modem.supported >= 3) //Might need to be escaped?
	{
		if (modem.passthroughlinestatusdirty & 7) //Still pending to send the last line status?
		{
			return 0; //Don't send any yet! Wait for the transfer to become up-to-date first!
		}
		if (value == 0xFF) //Needs to be escaped?
		{
			if (fifobuffer_freesize(modem.outputbuffer[0]) < 2) //Not enough room to send?
			{
				return 0; //Don't send yet!
			}
			writefifobuffer(modem.outputbuffer[0], 0xFF); //Escape the value to write to make it to the other side!
		}
		//Doesn't need to be escaped for any other value!
	}
	return writefifobuffer(modem.outputbuffer[0],value); //Try to write to the output buffer!
}

byte readIPnumber(char **x, byte *number)
{
	byte size=0;
	word result=0;
	for (;(isdigit((int)*(*x)) && (size<3));) //Scan digits!
	{
		result = (result*10)+(*(*x)-'0'); //Convert to a number!
		++(*x); //Next digit!
		++size; //Size has been read!
	}
	if ((size==3) && (result<256)) //Valid IP part?
	{
		*number = (byte)result; //Give the result!
		return 1; //Read!
	}
	return 0; //Not a valid IP section!
}

byte modem_connect(char *phonenumber)
{
	sword connectionid;
	char ipaddress[256];
	byte a,b,c,d;
	char *p; //For normal port resolving!
	unsigned int port;
	if (PacketServer_running) return 0; //Never connect the modem emulation when we're running as a packet server!
	if (modem.ringing && (phonenumber==NULL) && (PacketServer_running==0)) //Are we ringing and accepting it?
	{
		modem.ringing = 0; //Not ringing anymore!
		modem.connected = 1; //We're connected!
		if (modem.supported >= 3) //Requires sending a special packet?
		{
			modem.passthroughlines = 0; //Nothing received yet!
			modem.passthroughlinestatusdirty |= 7; //Request the packet to send!
			modem.breakPending = 0; //Not pending yet!
		}
		return 1; //Accepted!
	}
	else if (phonenumber==NULL) //Not ringing, but accepting?
	{
		return 0; //Not connected!
	}
	if (PacketServer_running) return 0; //Don't accept when the packet server is running instead!
	if (modem.connected == 1) //Connected and dialing out?
	{
		if (TCP_DisconnectClientServer(modem.connectionid)) //Try and disconnect, if possible!
		{
			modem.connectionid = -1; //Not connected anymore if succeeded!
			fifobuffer_clear(modem.inputdatabuffer[0]); //Clear the output buffer for the next client!
			fifobuffer_clear(modem.outputbuffer[0]); //Clear the output buffer for the next client!
			modem.connected = 0; //Not connected anymore!
		}
	}
	memset(&ipaddress,0,sizeof(ipaddress)); //Init IP address to translate!
	if (safestrlen(phonenumber,256)>=12) //Valid length to convert IP addresses?
	{
		p = phonenumber; //For scanning the phonenumber!
		if (readIPnumber(&p,&a))
		{
			if (readIPnumber(&p,&b))
			{
				if (readIPnumber(&p,&c))
				{
					if (readIPnumber(&p,&d))
					{
						if (*p=='\0') //EOS?
						{
							//Automatic port?
							snprintf(ipaddress,sizeof(ipaddress),"%u.%u.%u.%u",a,b,c,d); //Formulate the address!
							port = modem.connectionport; //Use the default port as specified!
						}
						else if (*p==':') //Port might follow?
						{
							++p; //Skip character!
							if (sscanf(p,"%u",&port)==0) //Port incorrectly read?
							{
								return 0; //Fail: invalid port has been specified!
							}
							snprintf(ipaddress,sizeof(ipaddress),"%u.%u.%u.%u",a,b,c,d);
						}
						else //Invalid?
						{
							goto plainaddress; //Plain address inputted?
						}
					}
					else
					{
						goto plainaddress; //Take as plain address!
					}
				}
				else
				{
					goto plainaddress; //Take as plain address!
				}
			}
			else
			{
				goto plainaddress; //Take as plain address!
			}
		}
		else
		{
			goto plainaddress; //Take as plain address!
		}
	}
	else
	{
		plainaddress: //A plain address after all?
		if ((p = strrchr(phonenumber,':'))!=NULL) //Port is specified?
		{
			safestrcpy(ipaddress,sizeof(ipaddress),phonenumber); //Raw IP with port!
			ipaddress[(ptrnum)p-(ptrnum)phonenumber] = '\0'; //Cut off the port part!
			++p; //Take the port itself!
			if (sscanf(p,"%u",&port)==0) //Port incorrectly read?
			{
				return 0; //Fail: invalid port has been specified!
			}
		}
		else //Raw address?
		{
			safestrcpy(ipaddress,sizeof(ipaddress),phonenumber); //Use t
			port = modem.connectionport; //Use the default port as specified!
		}
	}
	if ((connectionid = TCP_ConnectClient(ipaddress,port))>=0) //Connected on the port specified(use the server port by default)?
	{
		modem.connectionid = connectionid; //We're connected to this!
		modem.connected = 1; //We're connected!
		if (modem.supported >= 3) //Requires sending a special packet?
		{
			modem.passthroughlines = 0; //Nothing received yet!
			modem.passthroughlinestatusdirty |= 7; //Request the packet to send!
			modem.breakPending = 0; //Not pending yet!
		}
		return 1; //We're connected!
	}
	return 0; //We've failed to connect!
}

void modem_hangup() //Hang up, if possible!
{
	if (modem.connected == 1) //Connected?
	{
		TCP_DisconnectClientServer(modem.connectionid); //Try and disconnect, if possible!
		modem.connectionid = -1; //Not connected anymore
		fifobuffer_clear(modem.inputdatabuffer[0]); //Clear the output buffer for the next client!
		fifobuffer_clear(modem.outputbuffer[0]); //Clear the output buffer for the next client!
	}
	modem.connected &= ~1; //Not connected anymore!
	modem.ringing = 0; //Not ringing anymore!
	modem.offhook = 0; //We're on-hook!
	fifobuffer_clear(modem.inputdatabuffer[0]); //Clear anything we still received!
	fifobuffer_clear(modem.outputbuffer[0]); //Clear anything we still need to send!
}

void modem_updateRegister(byte reg)
{
	switch (reg) //What reserved reg to emulate?
	{
		case 2: //Escape character?
			if (modem.escapecharacter!=modem.registers[reg]) //Escape character changed?
			{
				for (;modem.escaping;--modem.escaping) //Process all escaped data!
				{
					modem_sendData(modem.escapecharacter); //Send all escaped data!
				}
			}
			modem.escapecharacter = modem.registers[reg]; //Escape!
			break;
		case 3: //CR character?
			modem.carriagereturncharacter = modem.registers[reg]; //Escape!
			break;
		case 4: //Line feed character?
			modem.linefeedcharacter = modem.registers[reg]; //Escape!
			break;
		case 5: //Backspace character?
			modem.backspacecharacter = modem.registers[reg]; //Escape!
			break;
		case 12: //Escape code guard time?
			#ifdef IS_LONGDOUBLE
			modem.escapecodeguardtime = (modem.registers[reg]*20000000.0L); //Set the escape code guard time, in nanoseconds!
			#else
			modem.escapecodeguardtime = (modem.registers[reg]*20000000.0); //Set the escape code guard time, in nanoseconds!
			#endif
			break;
		case 25: //DTR to DSR Delay Interval(hundredths of a second)
			#ifdef IS_LONGDOUBLE
			modem.effectiveDTRlineDelay = (modem.registers[reg] * 10000000.0L); //Set the RTC to CTS line delay, in nanoseconds!
			#else
			modem.effectiveDTRlineDelay = (modem.registers[reg] * 10000000.0); //Set the RTC to CTS line delay, in nanoseconds!
			#endif
			break;
		case 26: //RTC to CTS Delay Interval(hundredths of a second)
			#ifdef IS_LONGDOUBLE
			modem.effectiveRTSlineDelay = (modem.registers[reg] * 10000000.0L); //Set the RTC to CTS line delay, in nanoseconds!
			#else
			modem.effectiveRTSlineDelay = (modem.registers[reg] * 10000000.0); //Set the RTC to CTS line delay, in nanoseconds!
			#endif
			break;
		default: //Unknown/unsupported?
			break;
	}
}

byte useSERModem() //Serial mouse enabled?
{
	return modem.supported; //Are we supported?
}

byte loadModemProfile(byte state)
{
	if (state==0) //OK?
	{
		return 1; //OK: loaded state!
	}
	return 0; //Default: no states stored yet!
}

byte resetModem(byte state)
{
	word reg;
	memset(&modem.registers,0,sizeof(modem.registers)); //Initialize the registers!
	//Load general default state!
	modem.registers[0] = 0; //Number of rings before auto-answer
	modem.registers[1] = 0; //Ring counter
	modem.registers[2] = 43; //Escape character(+, ASCII)
	modem.registers[3] = 0xD; //Carriage return character(ASCII)
	modem.registers[4] = 0xA; //Line feed character(ASCII)
	modem.registers[5] = 0x8; //Back space character(ASCII)
	modem.registers[6] = 2; //Wait time before blind dialing(seconds).
	modem.registers[7] = 50; //Wait for carrier after dial(seconds(+1))
	modem.registers[8] = 2; //Pause time for ,(dial delay, seconds)
	modem.registers[9] = 6; //Carrier detect response time(tenths of a seconds(+1)) 
	modem.registers[10] = 14; //Delay between Loss of Carrier and Hang-up(tenths of a second)
	modem.registers[11] = 95; //DTMF Tone duration(50-255 milliseconds)
	modem.registers[12] = 50; //Escape code guard time(fiftieths of a second)
	modem.registers[18] = 0; //Test timer(seconds)
	modem.registers[25] = 5; //Delay to DTR(seconds in synchronous mode, hundredths of a second in all other modes)
	modem.registers[26] = 1; //RTC to CTS Delay Interval(hundredths of a second)
	modem.registers[30] = 0; //Inactivity disconnect timer(tens of seconds). 0=Disabled
	modem.registers[37] = 0; //Desired Telco line speed(0-10. 0=Auto, otherwise, speed)
	modem.registers[38] = 20; //Delay before Force Disconnect(seconds)
	for (reg=0;reg<256;++reg)
	{
		modem_updateRegister((byte)reg); //This register has been updated!
	}

	/*

	According to , defaults are:
	B0: communicationstandard=0
	E1: echomode=1
	F0
	L3: speakervolume=3
	M1: speakercontrol=1
	N1
	Q0: verbosemode=(value)<<1|(verbosemode&1)
	T
	V1: verboseemode=(value)|verbosemode
	W1
	X4: callprogressmethod=4
	Y0
	&C1: DCDmodeisCarrier=1
	&D2: DTRoffRresponse=2
	&K3: flowcontrol=3
	&Q5: communicatinsmode=5
	&R1: CTSalwaysActive=1
	&S0: DSRisConnectionEstablished=0
	\A1
	\B3
	\K5
	\N3: 
	%C3
	%E2

	*/
	modem.communicationstandard = 0; //Default communication standard!
	modem.echomode = 1; //Default: echo back!
	//Speaker controls
	modem.speakervolume = 3; //Max level speaker volume!
	modem.speakercontrol = 1; //Enabled speaker!
	//Result defaults
	modem.verbosemode = 1; //Text-mode verbose!
	modem.callprogressmethod = 4;
	//Default handling of the Hardware lines is also loaded:
	modem.DCDisCarrier = 1; //Default: DCD=Set Data Carrier Detect (DCD) signal according to remote modem data carrier signal..
	modem.DTROffResponse = 2; //Default: Hang-up and Goto AT command mode?!
	modem.flowcontrol = 3; //Default: Enable RTS/CTS flow control!
	modem.communicationsmode = 5; //Default: communications mode 5 for V-series system products, &Q0 for Smartmodem products! So use &Q5 here!
	modem.CTSAlwaysActive = 1; //Default: CTS controlled by flow control!
	modem.DSRisConnectionEstablished = 0; //Default: DSR always ON!
	//Finish up the default settings!
	modem.datamode = 0; //In command mode!

	memset(&modem.lastnumber,0,sizeof(modem.lastnumber)); //No last number!
	modem.offhook = 0; //On-hook!
	if (modem.connected&1) //Are we still connected?
	{
		modem.connected &= ~1; //Disconnect!
		modem_responseResult(MODEMRESULT_NOCARRIER); //Report no carrier!
		TCP_DisconnectClientServer(modem.connectionid); //Disconnect the client!
		modem.connectionid = -1; //Not connected anymore!
		fifobuffer_clear(modem.inputdatabuffer[0]); //Clear the output buffer for the next client!
		fifobuffer_clear(modem.outputbuffer[0]); //Clear the output buffer for the next client!
	}


	//Misc data
	memset(&modem.previousATCommand,0,sizeof(modem.previousATCommand)); //No previous command!

	if (loadModemProfile(state)) //Loaded?
	{
		return 1; //OK!
	}
	return 0; //Invalid profile!
}

void MODEM_sendAutodetectionPNPmessage()
{
	if (modem.supported >= 2) return; //Don't handle responses in passthrough mode!
	//return; //We don't know what to send yet, so disable the PNP feature for now!
	//According to https://git.kontron-electronics.de/linux/linux-imx-exceet/blob/115a57c5b31ab560574fe1a09deaba2ae89e77b5/drivers/serial/8250_pnp.c , PNPC10F should be a "Standard Modem".
	//"PNPC10F"=Standard Modem. Order is(in order of escapes: Version(two 5-bits values, divided by 100 is the version number, high 5-bits first, low 5-bits second) ID("PNP"), product ID(the ID), Serial number(00000001), Class name("MODEM", as literally in the Plug and Play Exernal COM Device Specification Version 1.00 February 28, 1995), Device ID("," followed by the ID), User name("Modem", this is what's reported to the user as plain text).
	//The ID used to be "PNPC10F". Use PNPC102 for a safe Standard 28800bps modem.
	char EISA_productID[] = "PNPC107"; //Product ID! Standard modem?
	char DeviceID[] = "\\PNPC107"; //Device ID! Standard modem?
	char PNPHeader[] = "\x28\x01\x24"; //Header until EISA/product ID
	char PNPMid[] = "\\00000001\\MODEM"; //After EISA/product ID until Device ID
	char PNPFooter[] = "\\ModemCC\x29"; //Footer with checksum!
	char message[256]; //Buffer for the message to be modified into!
	memset(&message, 0, sizeof(message)); //Init the message to fill!
	word size;
	byte checksum;
	char *p, *e;
	//Start generating the checksum!
	checksum = 0; //Init checksum!
	//Copy the initial buffer data over(excluding checksum)!
	safestrcat(message,sizeof(message),PNPHeader); //Copy the message over to the actual buffer!
	safestrcat(message,sizeof(message),EISA_productID); //Copy the product ID over!
	safestrcat(message,sizeof(message),PNPMid); //Copy the second part of the message to the actual buffer!
	safestrcat(message,sizeof(message),DeviceID); //Copy the device ID over!
	safestrcat(message,sizeof(message),PNPFooter); //Copy the footer over!
	size = safe_strlen(message,sizeof(message)); //Size to send! Sizeof includes a final NULL byte, which we don't want to include! Taking sizeof's position gives us the byte past the string!
	e = &message[size-1]; //End of the message buffer(when to stop processing the checksum(the end PnP character). This selects from after the start byte until before the end byte, excluding the checksum itself)!
	p = &message[1]; //Init message to calculate the checksum(a ROMmed constant) to the first used byte(the byte after the start of the )!
	message[size - 2] = 0; //Second checksum nibble isn't counted!
	message[size - 3] = 0; //First checksum nibble isn't counted!
	for (;(p!=e);) //Not finished processing the entire checksum?
	{
		checksum += *p++; //Add to the checksum(minus the actual checksum bytes)! Also copy to the active message buffer!
	}
	checksum &= 0xFF; //It's MOD 256 for all but the checksum fields itself to get the actual checksum!
	message[size - 2] = ((checksum & 0xF) > 0xA) ? (((checksum & 0xF) - 0xA) + (byte)'A') : ((checksum & 0xF) + (byte)'0'); //Convert hex digit the low nibble checksum!
	message[size - 3] = (((checksum>>4) & 0xF) > 0xA) ? ((((checksum>>4) & 0xF) - 0xA) + (byte)'A') : (((checksum>>4) & 0xF) + (byte)'0'); //Convert hex digit the high nibble checksum!

	//The PNP message is now ready to be sent to the Data Terminal!

	fifobuffer_clear(modem.inputbuffer); //Clear the input buffer for out message!
	char c;
	p = &message[0]; //Init message!
	e = &message[size]; //End of the message buffer! Don't include the terminating NULL character, so substract one to stop when reaching the NULL byte instead of directly after it!
	for (; (p!=e) && ((fifobuffer_freesize(modem.inputbuffer)>2));) //Process the message, until either finished or not enough size left!
	{
		c = *p++; //Read a character to send!
		writefifobuffer(modem.inputbuffer, c); //Write the character!
	}
	//Finally, the CR/LF combination is sent!
	writefifobuffer(modem.inputbuffer,modem.carriagereturncharacter);
	writefifobuffer(modem.inputbuffer,modem.linefeedcharacter);
}

void modem_updatelines(byte lines); //Prototype for modem_setModemControl!

void modem_setModemControl(byte line) //Set output lines of the Modem!
{
	//Handle modem specifics here!
	//0: Data Terminal Ready(we can are ready to work), 1: Request to Send(UART can receive data), 4=Set during mark state of the TxD line.
	if ((line & 0x10) == 0) //Mark not set?
	{
		//TxD isn't mark, the detection timers are stopped, as TxD is required to be mark when using the detection scheme!
		modem.detectiontimer[0] = (DOUBLE)0; //Stop timing!
		modem.detectiontimer[1] = (DOUBLE)0; //Stop timing!
	}
	modem.canrecvdata = (line&2); //Can we receive data?
	modem.TxDisMark = ((line & 0x10) >> 4); //Is TxD set to mark?
	modem.TxDisBreak = ((line & 0x20) >> 5); //Is TxD set to break?
	line &= 0x2F; //Ignore unused lines!
	modem.outputline = line; //The line that's output!
	if ((modem.linechanges^line)&2) //RTS changed?
	{
		modem.RTSlineDelay = modem.effectiveRTSlineDelay; //Start timing the CTS line delay!
		if (modem.RTSlineDelay) //Gotten a delay?
		{
			modem_updatelines(2 | 4); //Update RTS internally, don't acnowledge RTS to CTS yet!
		}
		else
		{
			modem_updatelines(2); //Update RTS internally, acnowledge RTS to CTS!
		}
	}
	if (((modem.linechanges^line)&1)) //DTR changed?
	{
		modem.DTRlineDelay = modem.effectiveDTRlineDelay; //Start timing the CTS line delay!
		if (modem.DTRlineDelay) //Gotten a delay?
		{
			modem_updatelines(1 | 4); //Update DTR, don't acnowledge yet!
		}
		else
		{
			modem_updatelines(1); //Update DTR, acnowledge!
		}
	}
	if ((modem.linechanges ^ line) & 0x20) //Break changed?
	{
		modem_updatelines(0x20); //Update Break internally, acnowledging it!
	}
	modem.linechanges = line; //Save for reference!
}

void modem_Answered(); //Prototype!

void modem_updatelines(byte lines)
{
	if ((lines & 4) == 0) //Update effective lines?
	{
		modem.effectiveline = ((modem.effectiveline & ~(lines & 3)) | (modem.outputline & (lines & 3))); //Apply the line(s)!
	}
	if ((((modem.effectiveline&1)==0) && ((modem.effectivelinechanges^modem.effectiveline)&1)) && ((lines&4)==0)) //Became not ready?
	{
		modem.detectiontimer[0] = (DOUBLE)0; //Stop timing!
		modem.detectiontimer[1] = (DOUBLE)0; //Stop timing!
		if (modem.supported < 2) //Able to respond normally?
		{
			switch (modem.DTROffResponse) //What reponse?
			{
			case 0: //Ignore the line?
				break;
			case 3: //Reset and Hang-up?
			case 2: //Hang-up and Goto AT command mode?
				if ((modem.connected & 1) || modem.ringing) //Are we connected?
				{
					modem_responseResult(MODEMRESULT_NOCARRIER); //No carrier!
					modem_hangup(); //Hang up!
				}
			case 1: //Goto AT command mode?
				modem.datamode = (byte)(modem.ATcommandsize = 0); //Starting a new command!
				if (modem.DTROffResponse == 3) //Reset as well?
				{
					resetModem(0); //Reset!
				}
				break;
			default:
				break;
			}
		}
		else if (modem.supported >= 3) //Line status is passed as well?
		{
			modem.passthroughlinestatusdirty |= 1; //DTR Line is dirty!
		}
	}
	else if ((((modem.outputline & 1) == 0) && ((modem.outputlinechanges ^ modem.outputline) & 1))) //Became not ready?
	{
		if (modem.supported >= 3) //Line status is passed as well?
		{
			modem.passthroughlinestatusdirty |= 1; //DTR Line is dirty!
		}
	}
	else if ((((modem.outputline & 1) == 1) && ((modem.outputlinechanges ^ modem.outputline) & 1))) //Became ready?
	{
		if (modem.supported >= 3) //Line status is passed as well?
		{
			modem.passthroughlinestatusdirty |= 1; //DTR Line is dirty!
		}
		if (modem.supported >= 4) //Manual dialling out is enabled using phonebook entry #0?
		{
			if (modem.connected != 1) //Not already connected on the modem?
			{
				char* c = &BIOS_Settings.phonebook[0][0]; //Phone book support for entry #0!
				safestrcpy((char*)&modem.lastnumber, sizeof(modem.lastnumber), c); //Set the last number!
				if (modem_connect(c)) //Try to dial said number!
				{
					modem_Answered(); //Answer!
				}
			}
		}
	}

	if (((modem.outputlinechanges ^ modem.outputline) & 0x20)!=0) //Changed break?
	{
		modem.passthroughlinestatusdirty |= 4; //Break Line is dirty!
	}

	if (modem.supported < 2) //Normal behaviour?
	{
		if (((modem.outputline & 1) == 1) && ((modem.outputlinechanges ^ modem.outputline) & 1) && (modem.TxDisMark)) //DTR set while TxD is mark?
		{
			modem.detectiontimer[0] = (DOUBLE)150000000.0; //Timer 150ms!
			modem.detectiontimer[1] = (DOUBLE)250000000.0; //Timer 250ms!
			//Run the RTS checks now!
		}
		if ((modem.outputline & 2) && (modem.detectiontimer[0])) //RTS and T1 not expired?
		{
		modem_startidling:
			modem.detectiontimer[0] = (DOUBLE)0; //Stop timing!
			modem.detectiontimer[1] = (DOUBLE)0; //Stop timing!
			goto finishupmodemlinechanges; //Finish up!
		}
		if ((modem.outputline & 2) && (!modem.detectiontimer[0]) && (modem.detectiontimer[1])) //RTS and T1 expired and T2 not expired?
		{
			//Send serial PNP message!
			MODEM_sendAutodetectionPNPmessage();
			goto modem_startidling; //Start idling again!
		}
		if ((modem.outputline & 2) && (!modem.detectiontimer[1])) //RTS and T2 expired?
		{
			goto modem_startidling; //Start idling again!
		}
	}
	else if ((modem.supported >= 3) && ((modem.outputline ^ modem.outputlinechanges) & 2)) //Line status is passed as well?
	{
		if ((modem.outputline ^ modem.outputlinechanges) & 2) //RTS is passed as well?
		{
			modem.passthroughlinestatusdirty |= 2; //RTS Line is dirty!
		}
		//Check for break as well? Break isn't supported as an output from the UART yet?
	}
finishupmodemlinechanges:
	modem.outputlinechanges = modem.outputline; //Save for reference!
	if ((lines & 4) == 0) //Apply effective line?
	{
		modem.effectivelinechanges = modem.effectiveline; //Save for reference!
	}
}

byte modem_hasData() //Do we have data for input?
{
	byte havedatatoreceive; //Do we have data to receive?
	byte temp;
	byte allowdatatoreceive; //Do we allow data to receive?
	havedatatoreceive = (peekfifobuffer(modem.inputbuffer, &temp) || (peekfifobuffer(modem.inputdatabuffer[0], &temp) && (modem.datamode == 1))); //Do we have data to receive?
	if (modem.supported >= 2) //Passthrough mode?
	{
		allowdatatoreceive = modem.canrecvdata; //Default: allow to receive if not blocked!
		if (modem.supported >= 3) //Lines as well?
		{
			allowdatatoreceive = 1; //Always allow data to receive!
		}
	}
	else if (modem.communicationsmode && (modem.communicationsmode < 4)) //Synchronous mode? CTS is affected!
	{
		allowdatatoreceive = ((modem.canrecvdata && ((modem.flowcontrol == 1) || (modem.flowcontrol == 3))) || ((modem.flowcontrol != 1) && (modem.flowcontrol != 3))); //Default: allow all data to receive!
		switch (modem.CTSAlwaysActive)
		{
		case 0: //Track RTS? V.25bis handshake!
			break;
		case 1: //Depends on the buffers! Only drop when required by flow control!
			break;
		case 2: //Always on?
			break;
		}
	}
	else //Asynchronous mode?
	{
		//Hayes documentation says it doesn't control CTS and RTS functions!
		allowdatatoreceive = 1; //Ignore any RTS input!
	}

	return (havedatatoreceive&&allowdatatoreceive); //Do we have data to receive and flow control allows it?
}

byte modem_getstatus()
{
	byte result = 0;
	result = 0;
	//0: Clear to Send(Can we buffer data to be sent), 1: Data Set Ready(Not hang up, are we ready for use), 2: Ring Indicator, 3: Carrrier detect, 4: Break
	if (modem.supported >= 2) //CTS depends on the outgoing buffer in passthrough mode!
	{
		result |= ((modem.datamode == 1) ? ((modem.connectionid >= 0) ? (fifobuffer_freesize(modem.outputbuffer[modem.connectionid]) ? 1 : 0) : 0) : 0); //Can we send to the modem?
		if (modem.supported >= 3) //Also depend on the received line!
		{
			result = (result & ~1) | ((modem.passthroughlines >> 1) & 1); //Mask CTS with received RTS!
		}
	}
	else if (modem.communicationsmode && (modem.communicationsmode < 4)) //Synchronous mode? CTS is affected!
	{
		switch (modem.CTSAlwaysActive)
		{
		case 0: //Track RTS? V.25bis handshake!
			result |= ((modem.outputline >> 1) & 1); //Track RTS, undelayed!
			break;
		case 1: //Depends on the buffers! Only drop when required by flow control!
			result |= ((modem.datamode == 1) ? ((modem.connectionid >= 0) ? (fifobuffer_freesize(modem.outputbuffer[modem.connectionid]) ? 1 : 0) : 1) : 1); //Can we send to the modem?
			break;
		case 2: //Always on?
			result |= 1; //Always on!
			break;
		}
	}
	else //Asynchronous mode?
	{
		//Hayes documentation says it doesn't control CTS and RTS functions!
		switch (modem.CTSAlwaysActive)
		{
		case 0: //RTS, delayed by S26 register's setting?
			result |= ((modem.effectiveline >> 1) & 1); //Track RTS, delayed!
			break;
		case 1: //Always on? RTS is ignored!
			result |= 1; //Always on! &Rn has no effect according to Hayes docs! But do this anyways!
			break;
		case 2: //Always on?
			result |= 1; //Always on!
			break;
		}
	}
	//DSRisConnectionEstablished: 0:1, 1:DTR
	if (modem.supported >= 2) //DTR depends on the outgoing connection in passthrough mode!
	{
		if ((modem.outputline & 1) == 1) //DTR is set? Then raise DSR when connected using the nullmodem line!
		{
			if ((modem.connected == 1) && (modem.datamode)) //Handshaked or pending handshake?
			{
				result |= 2; //Raise the line!
				if (modem.supported >= 3) //Also depend on the received line?
				{
					result = (result & ~2) | ((result & ((modem.passthroughlines << 1) & 2))); //Replace DSR with received DTR!
				}
			}
		}
	}
	else if ((modem.communicationsmode) && (modem.communicationsmode < 5)) //Special actions taken?
	{
		switch (modem.DSRisConnectionEstablished) //What state?
		{
		default:
		case 0: //S0?
		case 1: //S1?
			//0 at command state and idle, handshake(connected) turns on, lowered when hanged up.
			if ((modem.connected == 1) && (modem.datamode != 2)) //Handshaked?
			{
				result |= 2; //Raise the line!
			}
			//Otherwise, lower the line!
			break;
		case 2: //S2?
			//0 at command state and idle, prior to handshake turns on, lowered when hanged up.
			if ((modem.connected == 1) && (modem.datamode)) //Handshaked or pending handshake?
			{
				result |= 2; //Raise the line!
			}
			//Otherwise, lower the line!
			break;
		}
	}
	else //Q0/5/6?
	{
		switch (modem.DSRisConnectionEstablished) //What state?
		{
		default:
		case 0: //S0?
			result |= 2; //Always raised!
			break;
		case 1: //S1?
			result |= ((modem.outputline & 1) << 1); //Follow handshake!
			break;
		case 2: //S2?
			result |= ((modem.outputline & 1) << 1); //Follow handshake!
			break;
		}
	}
	result |= (((modem.ringing&1)&((modem.ringing)>>1))?4:0)| //Currently Ringing?
			(((modem.connected==1)||((modem.DCDisCarrier==0)&&(modem.supported<2)))?8:0); //Connected or forced on(never forced on for passthrough mode)?

	if (modem.supported >= 3) //Break is implemented?
	{
		result |= (((((modem.passthroughlines & 4) >> 2)&(fifobuffer_freesize(modem.inputdatabuffer[0])==MODEM_BUFFERSIZE))&1)<<4); //Set the break output when needed and not receiving anything anymore on the UART!
		if (likely(modem.breakPending == 0)) //Not break pending or pending anymore (preventing re-triggering without raising it again)?
		{
			result &= ~0x10; //Clear break signalling, as it's not pending yet or anymore!
		}
	}

	return result; //Give the resulting line status!
}

byte modem_readData()
{
	byte result,emptycheck;
	if (modem.breakPending && (fifobuffer_freesize(modem.inputbuffer) == MODEM_BUFFERSIZE) && (fifobuffer_freesize(modem.inputdatabuffer[0]) == MODEM_BUFFERSIZE)) //Break acnowledged by reading the result data?
	{
		modem.breakPending = 0; //Not pending anymore, acnowledged!
		return 0; //A break has this value (00h) read on it's data lines!
	}
	if (modem.datamode!=1) //Not data mode?
	{
		if (readfifobuffer(modem.inputbuffer, &result))
		{
			if ((modem.datamode==2) && (!peekfifobuffer(modem.inputbuffer,&emptycheck))) //Became ready to transfer data?
			{
				modem.datamode = 1; //Become ready to send!
			}
			return result; //Give the data!
		}
	}
	if (modem.datamode==1) //Data mode?
	{
		if (readfifobuffer(modem.inputdatabuffer[0], &result))
		{
			return result; //Give the data!
		}
	}
	return 0; //Nothing to give!
}

byte modemcommand_readNumber(word *pos, int *result)
{
	byte valid = 0;
	*result = 0;
	nextpos:
	switch (modem.ATcommand[*pos]) //What number?
	{
	case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9':
		*result = (*result*10)+(modem.ATcommand[*pos]-'0'); //Convert to a number!
		++*pos; //Next position to read!
		valid = 1; //We're valid!
		goto nextpos; //Read the next position!
		break;
	default: //Finished?
		break;
	}
	return valid; //Is the result valid?
}

void modem_Answered()
{
	if (modem.supported < 2) //Not passthrough mode?
	{
		modem_responseResult(MODEMRESULT_CONNECT); //Connected!
		modem.datamode = 2; //Enter data mode pending!
	}
	else
	{
		modem.datamode = 1; //Enter data mode!
	}
	modem.offhook = 1; //Off-hook(connect)!
}

void modem_executeCommand() //Execute the currently loaded AT command, if it's valid!
{
	char firmwareversion[] = "UniPCemu emulated modem V1.00\0"; //Firmware version!
	char hardwareinformation[] = "UniPCemu Hayes - compatible modem\0"; //Hardware information!
	char tempcommand[256]; //Stripped command with spaces removed!
	char tempcommand2[256]; //Stripped original case command with spaces removed!
	int n0;
	char number[256];
	byte dialproperties=0;
	memset(&number,0,sizeof(number)); //Init number!
	byte *temp, *temp2;
	byte verbosemodepending; //Pending verbose mode!

	temp = &modem.ATcommand[0]; //Parse the entire string!
	temp2 = &modem.ATcommandoriginalcase[0]; //Original case backup!
	for (; *temp;)
	{
		*temp2 = *temp; //Original case backup!
		*temp = (byte)toupper((int)*temp); //Convert to upper case!
		++temp; //Next character!
		++temp2; //Next character!
	}
	*temp2 = (char)0; //End of string!

	//Read and execute the AT command, if it's valid!
	if (strcmp((char *)&modem.ATcommand[0],"A/")==0) //Repeat last command?
	{
		memcpy(&modem.ATcommand,modem.previousATCommand,sizeof(modem.ATcommand)); //Last command again!
		//Re-case the command!
		temp = &modem.ATcommand[0]; //Parse the entire string!
		temp2 = &modem.ATcommandoriginalcase[0]; //Original case backup!
		for (; *temp;)
		{
			*temp2 = *temp; //Original case backup!
			*temp = (byte)toupper((int)*temp); //Convert to upper case!
			++temp; //Next character!
			++temp2; //Next character!
		}
		*temp2 = 0; //End of string!
		modem.detectiontimer[0] = (DOUBLE)0; //Stop timing!
		modem.detectiontimer[1] = (DOUBLE)0; //Stop timing!
	}

	//Check for a command to send!
	//Parse the AT command!

	if (modem.ATcommand[0]==0) //Empty line? Stop dialing and perform autoanswer!
	{
		modem.detectiontimer[0] = (DOUBLE)0; //Stop timing!
		modem.detectiontimer[1] = (DOUBLE)0; //Stop timing!
		return;
	}

	if (!((modem.ATcommand[0] == 'A') && (modem.ATcommand[1] == 'T'))) //Invalid header to the command?
	{
		modem_responseResult(MODEMRESULT_ERROR); //Error!
		return; //Abort!
	}

	if (modem.ATcommand[2] == 0) //Empty AT command? Just an "AT\r" command!
	{
		//Stop dialing and perform autoanswer!
		modem.registers[0] = 0; //Stop autoanswer!
		//Dialing doesn't need to stop, as it's instantaneous!
	}

	modem.detectiontimer[0] = (DOUBLE)0; //Stop timing!
	modem.detectiontimer[1] = (DOUBLE)0; //Stop timing!
	memcpy(&modem.previousATCommand,&modem.ATcommandoriginalcase,sizeof(modem.ATcommandoriginalcase)); //Save the command for later use!
	verbosemodepending = modem.verbosemode; //Save the old verbose mode, to detect and apply changes after the command is successfully completed!
	word pos=2,posbackup; //Position to read!
	byte SETGET = 0;
	word dialnumbers = 0;
	word temppos;
	char *c = &BIOS_Settings.phonebook[0][0]; //Phone book support

	memcpy(&tempcommand, &modem.ATcommand, MIN(sizeof(modem.ATcommand),sizeof(tempcommand))); //Make a copy of the current AT command for stripping!
	memcpy(&tempcommand2, &modem.ATcommandoriginalcase, MIN(sizeof(modem.ATcommandoriginalcase), sizeof(tempcommand2))); //Make a copy of the current AT command for stripping!
	memset(&modem.ATcommand, 0, sizeof(modem.ATcommand)); //Clear the command for the stripped version!
	memset(&modem.ATcommandoriginalcase, 0, sizeof(modem.ATcommandoriginalcase)); //Clear the command for the stripped version!
	posbackup = safe_strlen(tempcommand, sizeof(tempcommand)); //Store the length for fast comparison!
	for (pos = 0; pos < posbackup; ++pos) //We're stripping spaces!
	{
		if (tempcommand[pos] != ' ') //Not a space(which is ignored)? Linefeed is taken as is and errors out when encountered!
		{
			safescatnprintf((char *)&modem.ATcommand[0], sizeof(modem.ATcommand), "%c", tempcommand[pos]); //Add the valid character to the command!
		}
		if (tempcommand2[pos] != ' ') //Not a space(which is ignored)? Linefeed is taken as is and errors out when encountered!
		{
			safescatnprintf((char*)&modem.ATcommandoriginalcase[0], sizeof(modem.ATcommandoriginalcase), "%c", tempcommand2[pos]); //Add the valid character to the command!
		}
	}
	pos = 2; //Reset the position to the end of the AT identifier for the processing of the command!
	for (;;) //Parse the command!
	{
		switch (modem.ATcommand[pos++]) //What command?
		{
		case 0: //EOS? OK!
			handleModemCommandEOS:
			modem_responseResult(MODEMRESULT_OK); //OK
			modem.verbosemode = verbosemodepending; //New verbose mode, if set!
			return; //Finished processing the command!
		case 'E': //Select local echo?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATE;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0': //Off?
				n0 = 0;
				doATE:
				if (n0<2) //OK?
				{
					modem.echomode = n0; //Set the communication standard!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
				break;
			}
			break;
		case 'N': //Automode negotiation?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATN;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0': //Off?
				n0 = 0;
			doATN:
				if (n0 < 2) //OK?
				{
					//Not handled!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
				break;
			}
			break;
		case 'D': //Dial?
			do_ATD: //Phonebook ATD!
			switch (modem.ATcommandoriginalcase[pos++]) //What dial command?
			{
			case 'L':
				memcpy(&number,&modem.lastnumber,(safestrlen((char *)&modem.lastnumber[0],sizeof(modem.lastnumber))+1)); //Set the new number to roll!
				goto actondial;
			case 'A': //Reverse to answer mode after dialing?
				goto unsupporteddial; //Unsupported for now!
				dialproperties = 1; //Reverse to answer mode!
				goto actondial;
			case ';': //Remain in command mode after dialing
				dialproperties = 2; //Remain in command mode!
				goto dodial_tone;
			case ',': //Pause for the time specified in register S8(usually 2 seconds)
			case '!': //Flash-Switch hook (Hang up for half a second, as in transferring a call)
				goto unsupporteddial;
			case 0: //EOS?
				--pos; //Next command!
			case 'T': //Tone dial?
			case 'P': //Pulse dial?
			case 'W': //Wait for second dial tone?
			case '@': //Wait for up to	30 seconds for one or more ringbacks
			dodial_tone: //Perform a tone dial!
				//Scan for a remain in command mode modifier!
				for (temppos = pos; temppos < safe_strlen((char *)&modem.ATcommand[0], sizeof(modem.ATcommand)); ++temppos) //Scan the string!
				{
					switch (modem.ATcommand[temppos]) //Check for modifiers in the connection string!
					{
					case ';': //Remain in command mode after dialing
						dialproperties = 2; //Remain in command mode!
						break;
					case ',': //Pause for the time specified in register S8(usually 2 seconds)
					case '!': //Flash-Switch hook (Hang up for half a second, as in transferring a call)
						goto unsupporteddial;
					}
				}
				safestrcpy((char *)&number[0],sizeof(number),(char *)&modem.ATcommandoriginalcase[pos]); //Set the number to dial, in the original case!
				if (safestrlen((char *)&number[0],sizeof(number)) < 2 && number[0]) //Maybe a phone book entry? This is for easy compatiblity for quick dial functionality on unsupported software!
				{
					if (number[0] == ';') //Dialing ';', which means something special?
					{
						goto handleModemCommandEOS; //Special: trigger EOS for OK!
					}
					posbackup = pos; //Save the position!
					if (modemcommand_readNumber(&pos, &n0)) //Read a phonebook entry?
					{
						if (modem.ATcommand[pos] == '\0') //End of string? We're a quick dial!
						{
							if (n0 < 10) //Valid quick dial?
							{
								if (dialnumbers&(1<<n0)) goto badnumber; //Prevent looping!
								goto handleQuickDial; //Handle the quick dial number!
							}
							else //Not a valid quick dial?
							{
								badnumber: //Infinite recursive dictionary detected!
								pos = posbackup; //Return to where we were! It's a normal phonenumber!
							}
						}
						else
						{
							pos = posbackup; //Return to where we were! It's a normal phonenumber!
						}
					}
					else
					{
						pos = posbackup; //Return to where we were! It's a normal phonenumber!
					}
				}
				memset(&modem.lastnumber,0,sizeof(modem.lastnumber)); //Init last number!
				safestrcpy((char *)&modem.lastnumber,sizeof(modem.lastnumber),(char *)&number[0]); //Set the last number!
				actondial: //Start dialing?
				if (modem_connect(number))
				{
					modem_responseResult(MODEMRESULT_CONNECT); //Accept!
					modem.offhook = 2; //On-hook(connect)!
					if (dialproperties!=2) //Not to remain in command mode?
					{
						modem.datamode = 2; //Enter data mode pending!
					}
				}
				else //Dial failed?
				{
					modem_responseResult(MODEMRESULT_NOCARRIER); //No carrier!
				}
				modem.verbosemode = verbosemodepending; //New verbose mode, if set!
				return; //Nothing follows the phone number!
				break;
			case 'S': //Dial phonebook?
				posbackup = pos; //Save for returning later!
				if (modemcommand_readNumber(&pos, &n0)) //Read the number?
				{
					handleQuickDial: //Handle a quick dial!
					pos = posbackup; //Reverse to the dial command!
					--pos; //Return to the dial command!
					if (n0 > NUMITEMS(BIOS_Settings.phonebook)) goto invalidPhonebookNumberDial;
					snprintf((char *)&modem.ATcommand[pos], sizeof(modem.ATcommand) - pos, "%s",(char *)&BIOS_Settings.phonebook[n0]); //Select the phonebook entry based on the number to dial!
					snprintf((char*)&modem.ATcommandoriginalcase[pos], sizeof(modem.ATcommand) - pos, "%s", (char*)&BIOS_Settings.phonebook[n0]); //Select the phonebook entry based on the number to dial!
					if (dialnumbers & (1 << n0)) goto loopingPhonebookNumberDial; //Prevent looping of phonenumbers being quick dialed through the phonebook or through a single-digit phonebook shortcut!
					dialnumbers |= (1 << n0); //Handling noninfinite! Prevent dialing of this entry when quick dialed throuh any method!
					goto do_ATD; //Retry with the new command!
				loopingPhonebookNumberDial: //Loop detected?
					modem_responseResult(MODEMRESULT_NOCARRIER); //No carrier!
					return; //Abort!
				invalidPhonebookNumberDial: //Dialing invalid number?
					modem_responseResult(MODEMRESULT_ERROR);
					return; //Abort!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR);
					return; //Abort!
				}
				break;

			default: //Unsupported?
				--pos; //Retry analyzing!
				goto dodial_tone; //Perform a tone dial on this!
			unsupporteddial: //Unsupported dial function?
				modem_responseResult(MODEMRESULT_ERROR); //Error!
				return; //Abort!
				break;
			}
			break; //Dial?
		case 'A': //Answer?
			switch (modem.ATcommand[pos++]) //What type?
			{
			default: //Unknown values are next commands and assume 0!
			case 0: //EOS?
				--pos; //Next command!
			case '0': //Answer?
				if (modem_connect(NULL)) //Answered?
				{
					modem_Answered(); //Answer!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Not Connected!
					return; //Abort!
				}
				break;
			}
			break;
		case 'Q': //Quiet mode?
			switch (modem.ATcommand[pos++]) //What type?
			{
			default: //Unknown values are next commands and assume 0!
			case 0: //Assume 0!
				--pos; //Next command!
			case '0': //Answer? All on!
				n0 = 0;
				goto doATQ;
			case '1': //All off!
				n0 = 1;
				goto doATQ;
			case '2': //No ring and no Connect/Carrier in answer mode?
				n0 = 2;
				doATQ:
				if (n0<3)
				{
					verbosemodepending = (n0<<1)|(verbosemodepending&1); //Quiet mode!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //ERROR!
					return; //Abort!
				}
				break;
			}
			break;
		case 'H': //Select communication standard?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATH;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0': //Off hook?
				n0 = 0;
				doATH:
				if (n0<2) //OK?
				{
					modem.offhook = n0?1:0; //Set the hook status or hang up!
					if ((((modem.connected&1) || modem.ringing)&&(!modem.offhook)) || (modem.offhook && (!((modem.connected&1)||modem.ringing)))) //Disconnected or still ringing/connected?
					{
						if (modem.offhook==0) //On-hook?
						{
							modem_hangup(); //Hang up, if required!
						}
					}
					//Not connected? Simply report OK!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
				break;
			}
			break;
		case 'B': //Select communication standard?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATB;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0':
				n0 = 0;
				doATB:
				if (n0<2) //OK?
				{
					modem.communicationstandard = n0; //Set the communication standard!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
				break;
			}
			break;
		case 'L': //Select speaker volume?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATL;
			case '2':
				n0 = 2;
				goto doATL;
			case '3':
				n0 = 3;
				goto doATL;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0':
				n0 = 0;
				doATL:
				if (n0<4) //OK?
				{
					modem.speakervolume = n0; //Set the speaker volume!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
				break;
			}
			break;
		case 'M': //Speaker control?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATM;
			case '2':
				n0 = 2;
				goto doATM;
			case '3':
				n0 = 3;
				goto doATM;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0':
				n0 = 0;
				doATM:
				if (n0<4) //OK?
				{
					modem.speakercontrol = n0; //Set the speaker control!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
			}
			break;
		case 'V': //Verbose mode?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATV;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Nerxt command!
			case '0':
				n0 = 0;
				doATV:
				if (n0<2) //OK?
				{
					verbosemodepending = ((verbosemodepending&~1)|n0); //Set the verbose mode to numeric(0) or English(1)!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
				break;
			}
			break;
		case 'X': //Select call progress method?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATX;
			case '2':
				n0 = 2;
				goto doATX;
			case '3':
				n0 = 3;
				goto doATX;
			case '4':
				n0 = 4;
				goto doATX;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0':
				n0 = 0;
				doATX:
				modem.datamode = 0; //Mode not data!
				if (n0<5) //OK and supported by our emulation?
				{
					modem.callprogressmethod = n0; //Set the speaker control!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
				break;
			}
			break;
		case 'Z': //Reset modem?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATZ;
			default: //Unknown values are next commands and assume 0!
			case 0: //EOS?
				--pos; //Next command!
			case '0':
				n0 = 0;
				doATZ:
				if (n0<2) //OK and supported by our emulation?
				{
					if (resetModem(n0)) //Reset to the given state!
					{
						//Do nothing when succeeded! Give OK if no other errors occur!
					}
					else
					{
						modem_responseResult(MODEMRESULT_ERROR); //Error!
						return; //Abort!
					}
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error!
					return; //Abort!
				}
				break;
			}
			break;
		case 'T': //Tone dial?
		case 'P': //Pulse dial?
			break; //Ignore!
		case 'I': //Inquiry, Information, or Interrogation?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATI;
			case '2':
				n0 = 2;
				goto doATI;
			case '3':
				n0 = 3;
				goto doATI;
			case '4':
				n0 = 4;
				goto doATI;
			case '5':
				n0 = 5;
				goto doATI;
			case '6':
				n0 = 6;
				goto doATI;
			case '7':
				n0 = 7;
				goto doATI;
			case '8':
				n0 = 8;
				goto doATI;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0':
				n0 = 0;
				doATI:
				if (n0<5) //OK?
				{
					switch (n0) //What request?
					{
					case 3: //Firmware version!
						modem_responseString((byte *)&firmwareversion[0], (1 | 2 | 4)); //Full response!
						break;
					case 4: //Hardware information!
						modem_responseString((byte *)&hardwareinformation[0], (1 | 2 | 4)); //Full response!
						break;
					default: //Unknown!
						//Just respond with a basic OK!
						break;
					}
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR); //Error: line not defined!
					return; //Abort!
				}
				break;
			}
			break;
		case 'O': //Return online?
			switch (modem.ATcommand[pos++]) //What type?
			{
			case '1':
				n0 = 1;
				goto doATO;
			default: //Unknown values are next commands and assume 0!
			case 0:
				--pos; //Next command!
			case '0':
				n0 = 0;
				doATO:
				if (modem.connected & 1) //Connected?
				{
					modem.datamode = 1; //Return to data mode, no result code!
				}
				else
				{
					modem_responseResult(MODEMRESULT_ERROR);
					return; //Abort!
				}
				break;
			}
			break;
		case '?': //Query current register?
			modem_responseNumber(modem.registers[modem.currentregister]); //Give the register value!
			modem.verbosemode = verbosemodepending; //New verbose mode, if set!
			return; //Abort!
			break;
		case '=': //Set current register?
			if (modemcommand_readNumber(&pos,&n0)) //Read the number?
			{
				modem.registers[modem.currentregister] = n0; //Set the register!
				modem_updateRegister(modem.currentregister); //Update the register as needed!
			}
			else
			{
				modem_responseResult(MODEMRESULT_ERROR);
				return; //Abort!
			}
			break;
		case 'S': //Select register n as current register?
			if (modemcommand_readNumber(&pos,&n0)) //Read the number?
			{
				modem.currentregister = n0; //Select the register!
			}
			else
			{
				modem_responseResult(MODEMRESULT_ERROR);
				return; //Abort!
			}
			break;
		case '&': //Extension 1?
			switch (modem.ATcommand[pos++])
			{
			case 0: //EOS?
				modem_responseResult(MODEMRESULT_ERROR); //Error!
				return; //Abort command parsing!
			case 'Q': //Communications mode option?
				switch (modem.ATcommand[pos++]) //What flow control?
				{
				default: //Unknown values are next commands and assume 0!
				case 0:
					--pos; //Next command!
				case '0':
					n0 = 0; //
					goto setAT_EQ;
				case '1':
					n0 = 1; //
					goto setAT_EQ;
				case '2':
					n0 = 2; //
					goto setAT_EQ;
				case '3':
					n0 = 3; //
					goto setAT_EQ;
				case '4':
					n0 = 4; //
					goto setAT_EQ;
				case '5':
					n0 = 5; //
					goto setAT_EQ;
				case '6':
					n0 = 6; //
				setAT_EQ:
					if (n0 < 7) //Valid?
					{
						modem.communicationsmode = n0; //Set communications mode!
					}
					else
					{
						modem_responseResult(MODEMRESULT_ERROR); //Error!
						return; //Abort!
					}
					break;
				}
				break;
			case 'R': //Force CTS high option?
				switch (modem.ATcommand[pos++]) //What flow control?
				{
				default: //Unknown values are next commands and assume 0!
					--pos;
				case '0':
					n0 = 0; //Modem turns on the Clear To Send signal when it detects the Request To Send (RTS) signal from host.
					goto setAT_R;
				case '1':
					n0 = 1; //Modem ignores the Request To Send signal and turns on its Clear To Send signal when ready to receive data.
					goto setAT_R;
				case '2':
					n0 = 2; // *Clear To Send force on.
					setAT_R:
					if (n0<2) //Valid?
					{
						modem.CTSAlwaysActive = n0; //Set flow control!
					}
					else
					{
						modem_responseResult(MODEMRESULT_ERROR); //Error!
						return; //Abort!
					}
					break;
				}
				break;
			case 'C': //Force DCD to be carrier option?
				switch (modem.ATcommand[pos++]) //What flow control?
				{
				default: //Unknown values are next commands and assume 0!
					--pos;
				case '0':
					n0 = 0; // Keep Data Carrier Detect (DCD) signal always ON.
					goto setAT_C;
				case '1':
					n0 = 1; // * Set Data Carrier Detect (DCD) signal according to remote modem data carrier signal.
					setAT_C:
					if (n0<2) //Valid?
					{
						modem.DCDisCarrier = n0; //Set flow control!
					}
					else
					{
						modem_responseResult(MODEMRESULT_ERROR); //Error!
						return; //Abort!
					}
					break;
				}
				break;
			case 'S': //Force DSR high option?
				switch (modem.ATcommand[pos++]) //What flow control?
				{
				default: //Unknown values are next commands and assume 0!
					--pos;
				case '0':
					n0 = 0; // * Data Set Ready is forced on
					goto setAT_S;
				case '1':
					n0 = 1; // Data Set Ready to operate according to RS-232 specification(follow DTR)
					goto setAT_S;
				case '2':
					n0 = 2; //
				setAT_S:
					if (n0<3) //Valid?
					{
						modem.DSRisConnectionEstablished = n0; //Set flow control!
					}
					else
					{
						modem_responseResult(MODEMRESULT_ERROR); //Error!
						return; //Abort!
					}
					break;
				}
				break;
			case 'D': //DTR reponse option?
				switch (modem.ATcommand[pos++]) //What flow control?
				{
				default: //Unknown values are next commands and assume 0!
					--pos;
				case '0':
					n0 = 0; //Ignore DTR line from computer
					goto setAT_D;
				case '1':
					n0 = 1; //Goto AT command state when DTR On->Off
					goto setAT_D;
				case '2':
					n0 = 2; //Hang-up and Command mode when DTR On->Off
					goto setAT_D;
				case '3':
					n0 = 3; //Full reset when DTR On->Off
					setAT_D:
					if (n0<4) //Valid?
					{
						modem.DTROffResponse = n0; //Set DTR off response!
					}
					else
					{
						modem_responseResult(MODEMRESULT_ERROR); //Error!
						return; //Abort!
					}
					break;
				}
				break;
			case 'F': //Load defaults?
				n0 = 0; //Default configuration!
				goto doATZ; //Execute ATZ!
			case 'Z': //Z special?
				n0 = 10; //Default: acnowledge!
				SETGET = 0; //Default: invalid!
				switch (modem.ATcommand[pos++]) //What flow control?
				{
				default:
				case '\0': //EOS?
					goto handlePhoneNumberEntry; //Acnowledge!
					//Ignore!
					break;
				case '0': //Set stored number?
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9': //Might be phonebook?
					n0 = (modem.ATcommand[pos - 1])-(byte)'0'; //Find the number that's to use!
					if (n0 >= NUMITEMS(BIOS_Settings.phonebook))
					{
						n0 = 10; //Invalid entry!
						goto handlePhoneNumberEntry; //Handle it!
					}
					switch (modem.ATcommand[pos++]) //SET/GET detection!
					{
					case '?': //GET?
						SETGET = 1; //GET!
						goto handlePhoneNumberEntry;
						break;
					case '=': //SET?
						SETGET = 2; //SET!
						goto handlePhoneNumberEntry;
						break;
					default: //Invalid command!
						n0 = 10; //Simple acnowledge!
						goto handlePhoneNumberEntry;
						break;
					}
					break;

					handlePhoneNumberEntry: //Handle a phone number dictionary entry!
					if (n0<NUMITEMS(BIOS_Settings.phonebook)) //Valid?
					{
						switch (SETGET) //What kind of set/get?
						{
						case 1: //GET?
							modem_responseString((byte *)&BIOS_Settings.phonebook[n0], 1|2|4); //Give the phonenumber!
							break;
						case 2: //SET?
							memset(&BIOS_Settings.phonebook[n0], 0, sizeof(BIOS_Settings.phonebook[0])); //Init the phonebook entry!
							c = (char *)&modem.ATcommandoriginalcase[pos]; //What phonebook value to set!
							safestrcpy(BIOS_Settings.phonebook[n0], sizeof(BIOS_Settings.phonebook[0]), c); //Set the phonebook entry!
							break;
						default:
							goto ignorePhonebookSETGET;
							break;
						}
					}
					else
					{
						ignorePhonebookSETGET:
						modem_responseResult(MODEMRESULT_ERROR); //Error: invalid phonebook entry or command!
						return; //Abort!
					}
					break;
				}
				break;

			case 'K': //Flow control?
				switch (modem.ATcommand[pos++]) //What flow control?
				{
				default: //Unknown values are next commands and assume 0!
					--pos;
				case '0':
					n0 = 0;
					goto setAT_K;
				case '1':
					goto unsupportedflowcontrol; //Unsupported!
					n0 = 1;
					goto setAT_K;
				case '2':
					goto unsupportedflowcontrol; //Unsupported!
					n0 = 2;
					goto setAT_K;
				case '3':
					n0 = 3;
					goto setAT_K;
				case '4':
					goto unsupportedflowcontrol; //Unsupported!
					n0 = 4;
					setAT_K:
					if (n0<5) //Valid?
					{
						modem.flowcontrol = n0; //Set flow control!
					}
					else
					{
						unsupportedflowcontrol:
						modem_responseResult(MODEMRESULT_ERROR); //Error!
						return; //Abort!
					}
					break;
				}
				break;
			default: //Invalid extension?
				--pos; //Retry analyzing!
				modem_responseResult(MODEMRESULT_ERROR); //Invalid extension!
				return;
				break;
			}
			break;
		case '\\': //Extension 2?
			switch (modem.ATcommand[pos++])
			{
			case 0: //EOS?
				modem_responseResult(MODEMRESULT_ERROR); //Let us handle it!
				return; //Abort processing!
			case 'N': //Flow control?
				switch (modem.ATcommand[pos++]) //What flow control?
				{
				default: //Unknown values are next commands and assume 0!
					--pos; //Next command!
				case '0':
					n0 = 0;
					goto setAT_N;
				case '1':
					n0 = 1;
					goto setAT_N;
				case '2':
					n0 = 2;
					goto setAT_N;
				case '3':
					n0 = 3;
					goto setAT_N;
				case '4':
					n0 = 4;
					goto setAT_N;
				case '5':
					n0 = 5;
					setAT_N:
					if (n0<6) //Valid?
					{
						//Unused!
					}
					else //Error out?
					{
						modem_responseResult(MODEMRESULT_ERROR); //Error!
						return; //Abort!
					}
					break;
				}
				break;
			default: //Invalid extension?
				--pos; //Retry analyzing!
				modem_responseResult(MODEMRESULT_ERROR); //Invalid extension!
				return;
			}
			break;
		default: //Unknown instruction?
			modem_responseResult(MODEMRESULT_ERROR); //Just ERROR unknown commands!
			return; //Abort!
			break;
		} //Switch!
	}
}

void modem_flushCommandCompletion()
{
	//Perform linefeed-related things!
	modem.wascommandcompletionecho = 0; //Disable the linefeed echo!
	modem.wascommandcompletionechoTimeout = (DOUBLE)0; //Stop the timeout!

	//Start execution of the currently buffered command!
	modem.ATcommand[modem.ATcommandsize] = 0; //Terminal character!
	modem.ATcommandsize = 0; //Start the new command!
	modem_executeCommand();
}

byte modem_writeCommandData(byte value)
{
	if (modem.datamode) //Data mode?
	{
		modem.wascommandcompletionecho = 0; //Disable the linefeed echo!
		return modem_sendData(value); //Send the data!
	}
	else //Command mode?
	{
		if (modem.supported >= 2) return 1; //Don't allow sending commands when in passthrough mode!
		modem.timer = 0.0; //Reset the timer when anything is received!
		if (value == '~') //Pause stream for half a second?
		{
			modem.wascommandcompletionecho = 0; //Disable the linefeed echo!
			//Ignore this time?
			if (modem.echomode) //Echo enabled?
			{
				writefifobuffer(modem.inputbuffer, value); //Echo the value back to the terminal!
			}
		}
		else if (value == modem.backspacecharacter) //Backspace?
		{
			modem.wascommandcompletionecho = 0; //Disable the linefeed echo!
			if (modem.ATcommandsize) //Valid to backspace?
			{
				--modem.ATcommandsize; //Remove last entered value!
			}
			if (modem.echomode) //Echo enabled?
			{
				if (fifobuffer_freesize(modem.inputbuffer) >= 3) //Enough to add the proper backspace?
				{
					writefifobuffer(modem.inputbuffer, value); //Previous character movement followed by...
					writefifobuffer(modem.inputbuffer, ' '); //Space to clear the character followed by...
					writefifobuffer(modem.inputbuffer, value); //Another backspace to clear it, if possible!
				}
			}
		}
		else if (value == modem.carriagereturncharacter) //Carriage return? Execute the command!
		{
			if (modem.echomode) //Echo enabled?
			{
				modem.wascommandcompletionecho = 1; //Was command completion with echo!
				writefifobuffer(modem.inputbuffer, value); //Echo the value back to the terminal!
			}
			else
			{
				modem.wascommandcompletionecho = 2; //Was command completion without echo!
			}
			handlemodemCR:
			modem.wascommandcompletionechoTimeout = MODEM_COMMANDCOMPLETIONTIMEOUT; //Start the timeout on command completion!
		}
		else if (value) //Not NULL-terminator? Command byte!
		{
			if (modem.echomode || ((modem.wascommandcompletionecho==1) && (value==modem.linefeedcharacter))) //Echo enabled and command completion with echo?
			{
				if (modem.echomode || ((modem.wascommandcompletionecho == 1) && (value == modem.linefeedcharacter))) //To echo back?
				{
					writefifobuffer(modem.inputbuffer, value); //Echo the value back to the terminal!
				}
				if ((modem.wascommandcompletionecho && (value == modem.linefeedcharacter))) //Finishing echo and start of command execution?
				{
					modem_flushCommandCompletion(); //Start executing the command now!
					return 1; //Don't add to the buffer!
				}
			}
			if (modem.wascommandcompletionecho) //Finishing echo and start of command execution?
			{
				modem_flushCommandCompletion(); //Start executing the command now!
			}
			modem.wascommandcompletionecho = 0; //Disable the linefeed echo from now on!
			if (modem.ATcommandsize < (sizeof(modem.ATcommand) - 1)) //Valid to input(leave 1 byte for the terminal character)?
			{
				modem.ATcommand[modem.ATcommandsize++] = value; //Add data to the string!
				if (modem.ATcommandsize >= 4) //At least AT/at started and another AT/at might be entered after it?
				{
					if ( //Is the command string ended with...
						((modem.ATcommand[modem.ATcommandsize - 1] == 'T') && (modem.ATcommand[modem.ATcommandsize - 2] == 'A')) //Same case AT?
						|| ((modem.ATcommand[modem.ATcommandsize - 1] == 't') && (modem.ATcommand[modem.ATcommandsize - 2] == 'a')) //Same case at?
						)
					{
						fifobuffer_clear(modem.inputbuffer); //Make sure we have enough room for the backspaces to be received!
						for (; modem.ATcommandsize > 2;) //Simulate removing the entire string after AT for any automatic inputs for any parser!
						{
							modem_writeCommandData(modem.backspacecharacter); //Backspace once to remove a character and give a empty backspace character in the removed location!
						}
					}
				}
				if ((modem.ATcommand[0] != 'A') && (modem.ATcommand[0]!='a')) //Not a valid start?
				{
					modem.ATcommand[0] = 0;
					modem.ATcommandsize = 0; //Reset!
				}
				else if ((modem.ATcommandsize == 2) && (modem.ATcommand[1] != '/')) //Invalid repeat or possible attention(AT/at) request!
				{
					if (!( //Not either valid combination of AT or at to get the attention?
						((modem.ATcommand[1] == 'T') && (modem.ATcommand[0] == 'A')) //Same case AT?
						|| ((modem.ATcommand[1] == 't') && (modem.ATcommand[0] == 'a')) //Same case at?
						))
					{
						if ((modem.ATcommand[1] == 'A') || (modem.ATcommand[1] == 'a')) //Another start marker entered?
						{
							modem.ATcommand[0] = modem.ATcommand[1]; //Becomes the new start marker!
							--modem.ATcommandsize; //Just discard to get us back to inputting another one!
						}
						else //Invalid start marker after starting!
						{
							modem.ATcommand[0] = 0;
							modem.ATcommandsize = 0; //Reset!
						}
					}
				}
				else if ((modem.ATcommandsize == 2) && (modem.ATcommand[1] == '/')) //Doesn't need an carriage return?
				{
					if (modem.echomode) //Echo enabled?
					{
						modem.wascommandcompletionecho = 1; //Was command completion with echo!
					}
					else
					{
						modem.wascommandcompletionecho = 0; //Disable the linefeed echo!
					}
					goto handlemodemCR; //Handle the carriage return automatically, because A/ is received!
				}
			}
		}
	}
	return 1; //Received!
}

byte modem_writeData(byte value)
{
	//Handle the data sent to the modem!
	if ((value==modem.escapecharacter) && (modem.supported<2) && (modem.escapecharacter<=0x7F) && ((modem.escaping && (modem.escaping<3)) || ((modem.timer>=modem.escapecodeguardtime) && (modem.escaping==0)))) //Possible escape sequence? Higher values than 127 disables the escape character! Up to 3 escapes after the guard timer is allowed!
	{
		++modem.escaping; //Increase escape info!
	}
	else //Not escaping(anymore)?
	{
		for (;modem.escaping;) //Process escape characters as data!
		{
			--modem.escaping; //Handle one!
			modem_writeCommandData(modem.escapecharacter); //Send it as data/command!
		}
		if (!modem_writeCommandData(value)) //Send it as data/command! Not acnowledged?
		{
			return 0; //Don't acnowledge the send yet!
		}
	}
	modem.timer = 0.0; //Reset the timer when anything is received!
	return 1; //Acnowledged and sent!
}

void initModem(byte enabled) //Initialise modem!
{
	word i;
	memset(&modem, 0, sizeof(modem));
	modem.supported = enabled; //Are we to be emulated?
	if (useSERModem()) //Is this modem enabled?
	{
		modem.port = allocUARTport(); //Try to allocate a port to use!
		if (modem.port==0xFF) //Unable to allocate?
		{
			modem.supported = 0; //Unsupported!
			goto unsupportedUARTModem;
		}
		modem.connectionid = -1; //Default: not connected!
		modem.inputbuffer = allocfifobuffer(MIN(MODEM_BUFFERSIZE,NUMITEMS(modem.ATcommand)*3),0); //Small input buffer! Make sure it's large enough to contain all command buffer items in backspaces(3 for each character)!
		initPacketServerClients(); //Prepare the clients for use!
		Packetserver_availableClients = 0; //Init: 0 clients available!
		for (i = 0; i < MIN(MIN(NUMITEMS(modem.inputdatabuffer),NUMITEMS(modem.outputbuffer)),(Packetserver_totalClients?Packetserver_totalClients:1)); ++i) //Allocate buffers for server and client purposes!
		{
			modem.inputdatabuffer[i] = allocfifobuffer(MODEM_BUFFERSIZE, 0); //Small input buffer!
			modem.outputbuffer[i] = allocfifobuffer(MODEM_BUFFERSIZE, 0); //Small input buffer!
			if (modem.inputdatabuffer[i] && modem.outputbuffer[i]) //Both allocated?
			{
				if (Packetserver_clients[i].packetserver_receivebuffer) //Packet server buffers allocated?
				{
					++Packetserver_availableClients; //One more client available!
				}
			}
			else break; //Failed to allocate? Not available client anymore!
		}
		Packetserver_totalClients = Packetserver_availableClients; //Init: n clients available in total!
		if (modem.inputbuffer && modem.inputdatabuffer[0] && modem.outputbuffer[0]) //Gotten buffers?
		{
			modem.connectionport = BIOS_Settings.modemlistenport; //Default port to connect to if unspecified!
			if (modem.connectionport==0) //Invalid?
			{
				modem.connectionport = 23; //Telnet port by default!
			}
			TCP_ConnectServer(modem.connectionport,Packetserver_availableClients?Packetserver_availableClients:1); //Connect the server on the default port!
			resetModem(0); //Reset the modem to the default state!
			#ifdef IS_LONGDOUBLE
			modem.serverpolltick = (1000000000.0L/(DOUBLE)MODEM_SERVERPOLLFREQUENCY); //Server polling rate of connections!
			modem.networkpolltick = (1000000000.0L/(DOUBLE)MODEM_DATATRANSFERFREQUENCY); //Data transfer polling rate!
			#else
			modem.serverpolltick = (1000000000.0/(DOUBLE)MODEM_SERVERPOLLFREQUENCY); //Server polling rate of connections!
			modem.networkpolltick = (1000000000.0/(DOUBLE)MODEM_DATATRANSFERFREQUENCY); //Data transfer polling rate!
			#endif
			UART_registerdevice(modem.port, &modem_setModemControl, &modem_getstatus, &modem_hasData, &modem_readData, &modem_writeData); //Register our UART device!
		}
		else
		{
			if (modem.inputbuffer) free_fifobuffer(&modem.inputbuffer);
			for (i = 0; i < NUMITEMS(modem.inputdatabuffer); ++i)
			{
				if (modem.outputbuffer[i]) free_fifobuffer(&modem.outputbuffer[i]);
				if (modem.inputdatabuffer[i]) free_fifobuffer(&modem.inputdatabuffer[i]);
			}
		}
	}
	else
	{
		unsupportedUARTModem: //Unsupported!
		modem.inputbuffer = NULL; //No buffer present!
		memset(&modem.inputdatabuffer,0,sizeof(modem.inputdatabuffer)); //No buffer present!
		memset(&modem.outputbuffer, 0, sizeof(modem.outputbuffer)); //No buffer present!
	}
}

void PPPOE_finishdiscovery(sword connectedclient); //Prototype for doneModem!

void doneModem() //Finish modem!
{
	TicksHolder timing;
	word i;
	byte DHCPreleaseleasewaiting;
	initTicksHolder(&timing); //Initialize the timing!
	retryReleaseDHCPleasewait:
	DHCPreleaseleasewaiting = 0; //Default: nothing waiting!
	for (i = 0; i < NUMITEMS(Packetserver_clients); ++i) //Process all clients!
	{
		if (Packetserver_clients[i].used) //Connected?
		{
			PPPOE_finishdiscovery((sword)i); //Finish discovery, if needed!
			TCP_DisconnectClientServer(Packetserver_clients[i].connectionid); //Stop connecting!
			Packetserver_clients[i].connectionid = -1; //Unused!
			terminatePacketServer(i); //Stop the packet server, if used!
			if (Packetserver_clients[i].DHCP_acknowledgepacket.length) //We're still having a lease?
			{
				if (Packetserver_clients[i].packetserver_useStaticIP < 7) //Not in release phase yet?
				{
					PacketServer_startNextStage(i, PACKETSTAGE_DHCP);
					Packetserver_clients[i].packetserver_useStaticIP = 7; //Start the release of the lease!
					Packetserver_clients[i].used = 2; //Special use case: we're in the DHCP release-only state!
					DHCPreleaseleasewaiting = 1; //Waiting for release!
				}
				else //Still releasing?
				{
					DHCPreleaseleasewaiting = 1; //Waiting for release!
				}
			}
			else //Normal release?
			{
				normalFreeDHCP(i);
				freePacketserver_client(i); //Free the client!
			}
		}
	}
	if (DHCPreleaseleasewaiting) //Waiting for release?
	{
		delay(1); //Wait a little bit!
		updateModem(getnspassed(&timing)); //Time the DHCP only!
		goto retryReleaseDHCPleasewait; //Check again!
	}

	if (modem.inputbuffer) //Allocated?
	{
		free_fifobuffer(&modem.inputbuffer); //Free our buffer!
	}
	if (modem.outputbuffer[0] && modem.inputdatabuffer[0]) //Allocated?
	{
		for (i = 0; i < MIN(NUMITEMS(modem.inputdatabuffer), NUMITEMS(modem.outputbuffer)); ++i) //Allocate buffers for server and client purposes!
		{
			free_fifobuffer(&modem.outputbuffer[i]); //Free our buffer!
			free_fifobuffer(&modem.inputdatabuffer[i]); //Free our buffer!
		}
	}

	if (TCP_DisconnectClientServer(modem.connectionid)) //Disconnect client, if needed!
	{
		modem.connectionid = -1; //Not connected!
		//The buffers are already released!
	}
	stopTCPServer(); //Stop the TCP server!
}

void cleanModem()
{
	//Nothing to do!
}

byte packetServerAddWriteQueue(sword client, byte data) //Try to add something to the write queue!
{
	byte *newbuffer;
	if (Packetserver_clients[client].packetserver_transmitlength>= Packetserver_clients[client].packetserver_transmitsize) //We need to expand the buffer?
	{
		newbuffer = zalloc(Packetserver_clients[client].packetserver_transmitsize+1024,"MODEM_SENDPACKET",NULL); //Try to allocate a larger buffer!
		if (newbuffer) //Allocated larger buffer?
		{
			memcpy(newbuffer, Packetserver_clients[client].packetserver_transmitbuffer, Packetserver_clients[client].packetserver_transmitsize); //Copy the new data over to the larger buffer!
			freez((void **)&Packetserver_clients[client].packetserver_transmitbuffer, Packetserver_clients[client].packetserver_transmitsize,"MODEM_SENDPACKET"); //Release the old buffer!
			Packetserver_clients[client].packetserver_transmitbuffer = newbuffer; //The new buffer is the enlarged buffer, ready to have been written more data!
			Packetserver_clients[client].packetserver_transmitsize += 1024; //We've been increased to this larger buffer!
			Packetserver_clients[client].packetserver_transmitbuffer[Packetserver_clients[client].packetserver_transmitlength++] = data; //Add the data to the buffer!
			return 1; //Success!
		}
	}
	else //Normal buffer usage?
	{
		Packetserver_clients[client].packetserver_transmitbuffer[Packetserver_clients[client].packetserver_transmitlength++] = data; //Add the data to the buffer!
		return 1; //Success!
	}
	return 0; //Failed!
}

byte packetServerAddPacketBufferQueue(MODEM_PACKETBUFFER *buffer, byte data) //Try to add something to the discovery queue!
{
	byte* newbuffer;
	if (buffer->length >= buffer->size) //We need to expand the buffer?
	{
		newbuffer = zalloc(buffer->size + 1024, "MODEM_SENDPACKET", NULL); //Try to allocate a larger buffer!
		if (newbuffer) //Allocated larger buffer?
		{
			memcpy(newbuffer, buffer->buffer, buffer->size); //Copy the new data over to the larger buffer!
			freez((void **)&buffer->buffer, buffer->size, "MODEM_SENDPACKET"); //Release the old buffer!
			buffer->buffer = newbuffer; //The new buffer is the enlarged buffer, ready to have been written more data!
			buffer->size += 1024; //We've been increased to this larger buffer!
			buffer->buffer[buffer->length++] = data; //Add the data to the buffer!
			return 1; //Success!
		}
	}
	else //Normal buffer usage?
	{
		buffer->buffer[buffer->length++] = data; //Add the data to the buffer!
		return 1; //Success!
	}
	return 0; //Failed!
}

byte packetServerAddPacketBufferQueueBE16(MODEM_PACKETBUFFER* buffer, word data) //Try to add something to the discovery queue!
{
	if (packetServerAddPacketBufferQueue(buffer, ((data>>8) & 0xFF)))
	{
		if (packetServerAddPacketBufferQueue(buffer, (data & 0xFF)))
		{
			return 1; //Success!
		}
	}
	return 0; //Error!
}

byte packetServerAddPacketBufferQueueLE16(MODEM_PACKETBUFFER* buffer, word data) //Try to add something to the discovery queue!
{
	if (packetServerAddPacketBufferQueue(buffer, (data & 0xFF)))
	{
		if (packetServerAddPacketBufferQueue(buffer, ((data >> 8) & 0xFF)))
		{
			return 1; //Success!
		}
	}
	return 0; //Error!
}

void packetServerFreePacketBufferQueue(MODEM_PACKETBUFFER *buffer)
{
	if (buffer->buffer) //Valid buffer to free?
	{
		freez((void**)&buffer->buffer, buffer->size, "MODEM_SENDPACKET"); //Free it!
	}
	buffer->size = buffer->length = 0; //No length anymore!
}

char logpacket_outbuffer[0x20001]; //Buffer for storin the data!
char logpacket_filename[256]; //For storing the raw packet that's sent!
void logpacket(byte send, byte *buffer, uint_32 size)
{
	uint_32 i;
	char adding[3];
	memset(&logpacket_filename,0,sizeof(logpacket_filename));
	memset(&logpacket_outbuffer,0,sizeof(logpacket_outbuffer));
	memset(&adding,0,sizeof(adding));
	for (i=0;i<size;++i)
	{
		snprintf(adding,sizeof(adding),"%02X",buffer[i]); //Set and ...
		safestrcat(logpacket_outbuffer,sizeof(logpacket_outbuffer),adding); //... Add!
	}
	if (send)
	{
		dolog("ethernetcard","Sending packet:");
	}
	else
	{
		dolog("ethernetcard","Receiving packet:");
	}
	dolog("ethernetcard","%s",logpacket_outbuffer); //What's received/sent!
}

void authstage_startrequest(DOUBLE timepassed, sword connectedclient, char *request, byte nextstage)
{
	if (Packetserver_clients[connectedclient].packetserver_stage_byte == PACKETSTAGE_INITIALIZING)
	{
		memset(&Packetserver_clients[connectedclient].packetserver_stage_str, 0, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str));
		safestrcpy(Packetserver_clients[connectedclient].packetserver_stage_str, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str), request);
		Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
		Packetserver_clients[connectedclient].packetserver_credentials_invalid = 0; //No invalid field detected yet!
		Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_MESSAGE_DELAY; //Delay this until we start transmitting!
	}
	Packetserver_clients[connectedclient].packetserver_delay -= timepassed; //Delaying!
	if ((Packetserver_clients[connectedclient].packetserver_delay <= 0.0) || (!Packetserver_clients[connectedclient].packetserver_delay)) //Finished?
	{
		Packetserver_clients[connectedclient].packetserver_delay = (DOUBLE)0; //Finish the delay!
		if (writefifobuffer(modem.outputbuffer[connectedclient], Packetserver_clients[connectedclient].packetserver_stage_str[Packetserver_clients[connectedclient].packetserver_stage_byte])) //Transmitted?
		{
			if (++Packetserver_clients[connectedclient].packetserver_stage_byte == safestrlen(Packetserver_clients[connectedclient].packetserver_stage_str, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str))) //Finished?
			{
				PacketServer_startNextStage(connectedclient,nextstage); //Prepare for next step!
			}
		}
	}
}

//result: 0: busy, 1: Finished, 2: goto sendoutputbuffer
byte authstage_enterfield(DOUBLE timepassed, sword connectedclient, char* field, uint_32 size, byte specialinit, char charmask)
{
	byte textinputfield = 0;
	byte isbackspace = 0;
	if (Packetserver_clients[connectedclient].packetserver_stage_byte == PACKETSTAGE_INITIALIZING)
	{
		memset(field, 0, size);
		Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start filling!
		Packetserver_clients[connectedclient].packetserver_stage_byte_overflown = 0; //Not yet overflown!
		if (specialinit==1) //Special init for protocol?
		{
			#if defined(PACKETSERVER_ENABLED) && !defined(NOPCAP)
			if (!(BIOS_Settings.ethernetserver_settings.users[0].username[0] && BIOS_Settings.ethernetserver_settings.users[0].password[0])) //Gotten no credentials?
			{
				Packetserver_clients[connectedclient].packetserver_credentials_invalid = 0; //Init!
			}
			#endif
		}
	}
	if (peekfifobuffer(modem.inputdatabuffer[connectedclient], &textinputfield)) //Transmitted?
	{
		isbackspace = (textinputfield == 8) ? 1 : 0; //Are we backspace?
		if (isbackspace) //Backspace?
		{
			if (Packetserver_clients[connectedclient].packetserver_stage_byte == 0) goto ignorebackspaceoutputfield; //To ignore?
			//We're a valid backspace!
			if (fifobuffer_freesize(modem.outputbuffer[connectedclient]) < 3) //Not enough to contain backspace result?
			{
				return 2; //Not ready to process the writes!
			}
		}
		if (writefifobuffer(modem.outputbuffer[connectedclient], (isbackspace || (textinputfield == '\r') || (textinputfield == '\n') || (!charmask)) ? textinputfield : charmask)) //Echo back to user, encrypted if needed!
		{
			if (isbackspace) //Backspace requires extra data?
			{
				if (!writefifobuffer(modem.outputbuffer[connectedclient], ' ')) return 2; //Clear previous input!
				if (!writefifobuffer(modem.outputbuffer[connectedclient], textinputfield)) return 2; //Another backspace to end up where we need to be!
			}
		ignorebackspaceoutputfield: //Ignore the output part! Don't send back to the user!
			readfifobuffer(modem.inputdatabuffer[connectedclient], &textinputfield); //Discard the input!
			if ((textinputfield == '\r') || (textinputfield == '\n')) //Finished?
			{
				if ((Packetserver_clients[connectedclient].lastreceivedCRLFinput == 0) || (textinputfield == Packetserver_clients[connectedclient].lastreceivedCRLFinput)) //Not received LF of CRLF or CR of LFCR?
				{
					field[Packetserver_clients[connectedclient].packetserver_stage_byte] = '\0'; //Finish the string!
					Packetserver_clients[connectedclient].packetserver_credentials_invalid |= Packetserver_clients[connectedclient].packetserver_stage_byte_overflown; //Overflow has occurred?
					Packetserver_clients[connectedclient].lastreceivedCRLFinput = textinputfield; //This was what was last received as the CRLF input!
					return 1; //Finished!
				}
			}
			else
			{
				Packetserver_clients[connectedclient].lastreceivedCRLFinput = 0; //Clear the CRLF received flag: the last was neither!
				if (isbackspace) //Backspace?
				{
					field[Packetserver_clients[connectedclient].packetserver_stage_byte] = '\0'; //Ending!
					if (Packetserver_clients[connectedclient].packetserver_stage_byte) //Non-empty?
					{
						--Packetserver_clients[connectedclient].packetserver_stage_byte; //Previous character!
						field[Packetserver_clients[connectedclient].packetserver_stage_byte] = '\0'; //Erase last character!
					}
				}
				else if ((textinputfield == '\0') || ((Packetserver_clients[connectedclient].packetserver_stage_byte + 1U) >= size) || Packetserver_clients[connectedclient].packetserver_stage_byte_overflown) //Future overflow, overflow already occurring or invalid input to add?
				{
					Packetserver_clients[connectedclient].packetserver_stage_byte_overflown = 1; //Overflow detected!
				}
				else //Valid content to add?
				{
					field[Packetserver_clients[connectedclient].packetserver_stage_byte++] = textinputfield; //Add input!
				}
			}
		}
	}
	return 0; //Still busy!
}

union
{
	word wval;
	byte bval[2]; //Byte of the word values!
} NETWORKVALSPLITTER;

void PPPOE_finishdiscovery(sword connectedclient)
{
	ETHERNETHEADER ethernetheader, packetheader;
	uint_32 pos; //Our packet buffer location!
	if (!(Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer && Packetserver_clients[connectedclient].pppoe_discovery_PADS.length)) //Already disconnected?
	{
		return; //No discovery to disconnect!
	}
	memcpy(&ethernetheader.data, &Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer, sizeof(ethernetheader.data)); //Make a copy of the PADS ethernet header!

	//Send the PADT packet now!
	memcpy(&packetheader.dst, &ethernetheader.src, sizeof(packetheader.dst)); //Make a copy of the ethernet destination to use!
	memcpy(&packetheader.src, &ethernetheader.dst, sizeof(packetheader.src)); //Make a copy of the ethernet source to use!
	memcpy(&packetheader.type, &ethernetheader.type, sizeof(packetheader.type)); //Make a copy of the ethernet type to use!

	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADT); //Clear the packet!

	//First, the ethernet header!
	for (pos = 0; pos < sizeof(packetheader.data); ++pos)
	{
		packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADT, packetheader.data[pos]); //Send the header!
	}

	//Now, the PADT packet!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADT); //Clear the packet!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADT, 0x11); //V/T!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADT, 0xA7); //PADT!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer[sizeof(ethernetheader.data)+2]); //Session_ID first byte!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer[sizeof(ethernetheader.data)+3]); //Session_ID second byte!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, 0x00); //Length first byte!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, 0x00); //Length second byte!
	//Now, the packet is fully ready!
	if (Packetserver_clients[connectedclient].pppoe_discovery_PADR.length != 0x14) //Packet length mismatch?
	{
		packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADT); //PADR not ready to be sent yet!
	}
	else //Send the PADR packet!
	{
		//Send the PADR packet that's buffered!
		sendpkt_pcap(Packetserver_clients[connectedclient].pppoe_discovery_PADT.buffer, Packetserver_clients[connectedclient].pppoe_discovery_PADT.length); //Send the packet to the network!
	}

	//Since we can't be using the buffers after this anyways, free them all!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI); //No PADI anymore!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADO); //No PADO anymore!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR); //No PADR anymore!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADS); //No PADS anymore!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADT); //No PADT anymore!
}

byte PPPOE_requestdiscovery(sword connectedclient)
{
	byte broadcastmac[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; //Broadcast address!
	uint_32 pos; //Our packet buffer location!
	ETHERNETHEADER packetheader;
	//Now, the PADI packet!
	memcpy(&packetheader.dst, broadcastmac, sizeof(packetheader.dst)); //Broadcast it!
	memcpy(&packetheader.src, maclocal, sizeof(packetheader.src)); //Our own MAC address as the source!
	packetheader.type = SDL_SwapBE16(0x8863); //Type!
	packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI); //Clear the packet!
	for (pos = 0; pos < sizeof(packetheader.data); ++pos)
	{
		packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, packetheader.data[pos]); //Send the header!
	}
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, 0x11); //V/T!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, 0x09); //PADT!
	//Now, the contents of th packet!
	NETWORKVALSPLITTER.wval = SDL_SwapBE16(0); //Session ID!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, NETWORKVALSPLITTER.bval[0]); //First byte!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, NETWORKVALSPLITTER.bval[1]); //Second byte!
	NETWORKVALSPLITTER.wval = SDL_SwapBE16(0x4); //Length!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, NETWORKVALSPLITTER.bval[0]); //First byte!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, NETWORKVALSPLITTER.bval[1]); //Second byte!
	NETWORKVALSPLITTER.wval = SDL_SwapBE16(0x0101); //Tag type: Service-Name!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, NETWORKVALSPLITTER.bval[0]); //First byte!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, NETWORKVALSPLITTER.bval[1]); //Second byte!
	NETWORKVALSPLITTER.wval = SDL_SwapBE16(0); //Tag length!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, NETWORKVALSPLITTER.bval[0]); //First byte!
	packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI, NETWORKVALSPLITTER.bval[1]); //Second byte!

	//Now, the packet is fully ready!
	if (Packetserver_clients[connectedclient].pppoe_discovery_PADI.length != 0x18) //Packet length mismatch?
	{
		packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI); //PADR not ready to be sent yet!
		return 0; //Failure!
	}
	else //Send the PADR packet!
	{
		//Send the PADR packet that's buffered!
		sendpkt_pcap(Packetserver_clients[connectedclient].pppoe_discovery_PADI.buffer, Packetserver_clients[connectedclient].pppoe_discovery_PADI.length); //Send the packet to the network!
	}
	return 1; //Success!
}

byte PPPOE_handlePADreceived(sword connectedclient)
{
	uint_32 pos; //Our packet buffer location!
	word length,sessionid,requiredsessionid;
	byte code;
	//Handle a packet that's currently received!
	ETHERNETHEADER ethernetheader, packetheader;
	if (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe == 0) return 0; //Invalid: not using PPPOE!
	memcpy(&ethernetheader.data, &Packetserver_clients[connectedclient].packet[0], sizeof(ethernetheader.data)); //Make a copy of the ethernet header to use!
	//Handle the CheckSum after the payload here?
	code = Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 1]; //The code field!
	if (Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data)] != 0x11) return 0; //Invalid V/T fields!
	memcpy(&length, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 4],sizeof(length)); //Length field!
	memcpy(&sessionid, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 2], sizeof(sessionid)); //Session_ID field!
	if (Packetserver_clients[connectedclient].pppoe_discovery_PADI.buffer) //PADI sent?
	{
		if(Packetserver_clients[connectedclient].pppoe_discovery_PADO.buffer) //PADO received?
		{
			if (Packetserver_clients[connectedclient].pppoe_discovery_PADR.buffer) //PADR sent?
			{
				if (Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer==NULL) //Waiting for PADS to arrive?
				{
					if (sessionid) return 0; //No session ID yet!
					if (code != 0x65) return 0; //No PADS yet!
					//We've received our PADO!
					//Ignore it's contents for now(unused) and accept always!
					for (pos = 0; pos < Packetserver_clients[connectedclient].pktlen; ++pos) //Add!
					{
						packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADO, Packetserver_clients[connectedclient].packet[pos]); //Add to the buffer!
					}
					return 1; //Handled!
				}
				else //When PADS is received, we're ready for action for normal communication! Handle PADT packets!
				{
					memcpy(&requiredsessionid, &Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer[sizeof(ethernetheader.data) + 2], sizeof(sessionid)); //Session_ID field!
					if (code != 0xA7) return 0; //Not a PADT packet?
					if (sessionid != requiredsessionid) return 0; //Not our session ID?
					//Our session has been terminated. Clear all buffers!
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADI); //No PADI anymore!
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADO); //No PADO anymore!
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR); //No PADR anymore!
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADS); //No PADS anymore!
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADT); //No PADT anymore!
					return 1; //Handled!
				}
			}
			else //Need PADR to be sent?
			{
				//Send PADR packet now?
				//Ignore the received packet, we can't handle any!
				//Now, the PADR packet again!
				packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR); //Clear the packet!
				//First, the Ethernet header!
				memcpy(&ethernetheader, &Packetserver_clients[connectedclient].pppoe_discovery_PADO.buffer,sizeof(ethernetheader.data)); //The ethernet header that was used to send the PADO packet!
				memcpy(&packetheader.dst, &ethernetheader.src, sizeof(packetheader.dst)); //Make a copy of the ethernet destination to use!
				memcpy(&packetheader.src, &ethernetheader.dst, sizeof(packetheader.src)); //Make a copy of the ethernet source to use!
				memcpy(&packetheader.type, &ethernetheader.type, sizeof(packetheader.type)); //Make a copy of the ethernet type to use!
				for (pos = 0; pos < sizeof(packetheader.data); ++pos)
				{
					packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, packetheader.data[pos]); //Send the header!
				}
				packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, 0x11); //V/T!
				packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, 0x19); //PADR!
				for (pos = sizeof(ethernetheader.data) + 2; pos < Packetserver_clients[connectedclient].pppoe_discovery_PADO.length; ++pos) //Remainder of the PADO packet copied!
				{
					packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, Packetserver_clients[connectedclient].pppoe_discovery_PADO.buffer[pos]); //Send the remainder of the PADO packet!
				}
				//Now, the packet is fully ready!
				if (Packetserver_clients[connectedclient].pppoe_discovery_PADR.length != Packetserver_clients[connectedclient].pppoe_discovery_PADO.length) //Packet length mismatch?
				{
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR); //PADR not ready to be sent yet!
				}
				else //Send the PADR packet!
				{
					//Send the PADR packet that's buffered!
					sendpkt_pcap(Packetserver_clients[connectedclient].pppoe_discovery_PADR.buffer, Packetserver_clients[connectedclient].pppoe_discovery_PADR.length); //Send the packet to the network!
				}
				return 0; //Not handled!
			}
		}
		else //Waiting for PADO packet response? Parse any PADO responses!
		{
			if (sessionid) return 0; //No session ID yet!
			if (code != 7) return 0; //No PADO yet!
			//We've received our PADO!
			//Ignore it's contents for now(unused) and accept always!
			for (pos = 0; pos < Packetserver_clients[connectedclient].pktlen; ++pos) //Add!
			{
				packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADO, Packetserver_clients[connectedclient].packet[pos]); //Add to the buffer!
			}
			//Send the PADR packet now!
			memcpy(&packetheader.dst, &ethernetheader.src, sizeof(packetheader.dst)); //Make a copy of the ethernet destination to use!
			memcpy(&packetheader.src, &ethernetheader.dst, sizeof(packetheader.src)); //Make a copy of the ethernet source to use!
			memcpy(&packetheader.type, &ethernetheader.type, sizeof(packetheader.type)); //Make a copy of the ethernet type to use!

			//First, the ethernet header!
			for (pos = 0; pos < sizeof(packetheader.data); ++pos)
			{
				packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, packetheader.data[pos]); //Send the header!
			}

			//Now, the PADR packet!
			packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR); //Clear the packet!
			packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, 0x11); //V/T!
			packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, 0x19); //PADR!
			for (pos = sizeof(ethernetheader.data)+2; pos < Packetserver_clients[connectedclient].pktlen; ++pos) //Remainder of the PADO packet copied!
			{
				packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR, Packetserver_clients[connectedclient].packet[pos]); //Send the remainder of the PADO packet!
			}
			//Now, the packet is fully ready!
			if (Packetserver_clients[connectedclient].pppoe_discovery_PADR.length != Packetserver_clients[connectedclient].pktlen) //Packet length mismatch?
			{
				packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].pppoe_discovery_PADR); //PADR not ready to be sent yet!
				return 0; //Not handled!
			}
			else //Send the PADR packet!
			{
				//Send the PADR packet that's buffered!
				sendpkt_pcap(Packetserver_clients[connectedclient].pppoe_discovery_PADR.buffer,Packetserver_clients[connectedclient].pppoe_discovery_PADR.length); //Send the packet to the network!
			}
			return 1; //Handled!
		}
	}
	//No PADI sent? Can't handle anything!
	return 0; //Not handled!
}

/*

PPP packet (flag is before and after each packet, which is ignored for packets present(used for framing only). It's location is before and after the packet data, which is unescaped in the buffer):
* start of packet *
address (byte): always 0xFF
control (byte): always 0x03
protocol (word): the protocol that's sent/received.
info: the payload (variable length)
checksum (word or doubleword): HDLC CRC
* end of packet *
*/

//PPP_calcFCS: calculates the FCS of a PPP frame (minus PPP 0x7F bytes). This is transferred in little endian byte order.
//The value of a FCS check including FCS should be 0x0F47 when including the FCS calculated from the sender. When calculating the FCS for sending, the FCS field isn't included in the calculation. The FCS is always stored in little-endian format.

/*
LCP header:
Code (byte)
Length (word): Length including this header.
data (variable): Options as described below for the Option header.
*/

/*
Option header:
Type (byte)
Length (byte): Length including this header
data (variable, depending on the Type as well). Invalid or unrecognised length should result in a Configure-Nak.
*/

typedef struct
{
	byte* data; //Data pointer!
	uint_32 pos; //Reading position within the data!
	uint_32 size; //Size of the data!
} PPP_Stream;

void createPPPstream(PPP_Stream* stream, byte *data, uint_32 size)
{
	stream->data = data;
	stream->pos = 0; //Start of stream!
	stream->size = size; //The size of the stream!
}

byte createPPPsubstream(PPP_Stream* stream, PPP_Stream * substream, uint_32 size)
{
	if ((stream->size==0) || (size==0)) return 0; //Fail when no size to allocate from or to!
	if ((stream->size - stream->pos) < size) return 0; //Fail when no room left for the sub-stream!
	substream->data = &stream->data[stream->pos]; //Where to start the sub-stream!
	substream->pos = 0; //Start of stream!
	substream->size = size; //The size of the substream!
	return 1; //The Substream is valid!
}

byte PPP_consumeStream(PPP_Stream* stream, byte* result)
{
	if (stream->pos >= stream->size) return 0; //End of stream reached!
	*result = stream->data[stream->pos]; //Read the data!
	++stream->pos; //Increase pointer in the stream!
	return 1; //Consumed!
}

//result: -1: only managed to read 1 byte(result contains first byte), 0: failed completely, 1: Result read from stream!
sbyte PPP_consumeStreamBE16(PPP_Stream* stream, word* result)
{
	byte temp, temp2;
	if (PPP_consumeStream(stream, &temp)) //First byte!
	{
		if (PPP_consumeStream(stream, &temp2)) //Second byte!
		{
			*result = temp2 | (temp << 8); //Little endian word order!
			return 1; //Success!
		}
		*result = (temp<<8); //What we've read successfully!
		return -1; //Failed at 1 byte!
	}
	return 0; //Failed at 0 bytes!
}


sbyte PPP_consumeStreamLE16(PPP_Stream* stream, word* result)
{
	byte temp, temp2;
	if (PPP_consumeStream(stream, &temp)) //First byte!
	{
		if (PPP_consumeStream(stream, &temp2)) //Second byte!
		{
			*result = temp | (temp2 << 8); //Little endian word order!
			return 1; //Success!
		}
		*result = temp; //What we've read successfully!
		return -1; //Failed at 1 byte!
	}
	return 0; //Failed at 0 bytes!
}

byte PPP_peekStream(PPP_Stream* stream, byte* result)
{
	if (stream->pos >= stream->size) return 0; //End of stream reached!
	*result = stream->data[stream->pos]; //Read the data!
	return 1; //Consumed!
}

uint_32 PPP_streamdataleft(PPP_Stream* stream)
{
	return stream->size - stream->pos; //How much data is left to give!
}

static const word fcslookup[256] =
{
   0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
   0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
   0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
   0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
   0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
   0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
   0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
   0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
   0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
   0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
   0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
   0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
   0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
   0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
   0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
   0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
   0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
   0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
   0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
   0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
   0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
   0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
   0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
   0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
   0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
   0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
   0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
   0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
   0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
   0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
   0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
   0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
};

#define PPP_GOODFCS 0xf0b8

//isforpacket: 1 when creating a checksum for the packet, 0 when checking a packet checksum with this function.
word PPP_calcFCS(byte* buffer, uint_32 length, byte isforpacket)
{
	uint_32 pos;
	word fcs;
	fcs = 0xFFFF; //Starting value!
	for (pos = 0; pos < length; ++pos)
	{
		fcs = (fcs >> 8) ^ fcslookup[(fcs & 0xFF) ^ buffer[pos]]; //Calcalate FCS!
	}
	if (isforpacket) //Unchanged?
	{
		return SDL_SwapBE16(~fcs); //One's complement value! This is to be swapped to Big-Endian order to work properly (which added to the stream as big-endian makes it proper little-endian)!
	}
	return fcs; //Don't swap, as this is done by the write only(to provide a little-endian value in the stream)! The result for a checksum is just in our native ordering to check against the good FCS value!
}

byte ipxbroadcastaddr[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF}; //IPX Broadcast address
byte ipxnulladdr[6] = {0x00,0x00,0x00,0x00,0x00,0x00 }; //IPX Forbidden NULL address
byte ipxnegotiationnodeaddr[6] = { 0xFF,0xFF,0xFF,0xFF,0xFF,0xFE }; //IPX address negotiation address

//result: 1 for OK address. 0 for overflow! NULL and Broadcast addresses are skipped automatically. addrsizeleft should be 6 (the size of an IPX address)
byte incIPXaddr2(byte* ipxaddr, byte addrsizeleft) //addrsizeleft=6 for the address specified
{
	++*ipxaddr; //Increase the address!
	if (*ipxaddr == 0) //Overflow?
	{
		if (--addrsizeleft) //Something left?
		{
			return incIPXaddr2(--ipxaddr, --addrsizeleft); //Try the next upper byte!
		}
		else //Nothing left to increase?
		{
			return 0; //Error out!
		}
	}
	if (addrsizeleft == sizeof(ipxbroadcastaddr)) //No overflow for full address?
	{
		if (memcmp(ipxaddr - 5, &ipxnegotiationnodeaddr, sizeof(ipxnegotiationnodeaddr)) == 0) //Broadcast address?
		{
			return incIPXaddr2(ipxaddr, addrsizeleft); //Increase to the first address, which we'll use!
		}
		else if (memcmp(ipxaddr-5, &ipxbroadcastaddr, sizeof(ipxbroadcastaddr)) == 0) //Broadcast address?
		{
			incIPXaddr2(ipxaddr, addrsizeleft); //Increase to NULL address (forbidden), which we'll skip!
			return incIPXaddr2(ipxaddr, addrsizeleft); //Increase to the first address, which we'll use!
		}
		else if (memcmp(ipxaddr - 5, &ipxnulladdr, sizeof(ipxnulladdr)) == 0) //Null address?
		{
			return incIPXaddr2(ipxaddr, addrsizeleft); //Increase to the first address, which we'll use!
		}
	}
	return 1; //Address is OK!
}

//ipxaddr must point to the first byte of the address (it's in big endian format)
byte incIPXaddr(byte* ipxaddr)
{
	return incIPXaddr2(&ipxaddr[5], 6); //Increment the IPX address to a valid address from the LSB!
}

//ppp_responseforuser: a packet for an client has been placed for the client to receive.
void ppp_responseforuser(sword connectedclient)
{
	//A packet has arrived for an user. Prepare the user data for receiving the packet properly.
	Packetserver_clients[connectedclient].packetserver_packetpos = 0; //Reset packet position!
	Packetserver_clients[connectedclient].packetserver_bytesleft = Packetserver_clients[connectedclient].ppp_response.length; //How much to send!
	Packetserver_clients[connectedclient].PPP_packetreadyforsending = 1; //Ready, not pending anymore!
	Packetserver_clients[connectedclient].PPP_packetpendingforsending = 0; //Ready, not pending anymore!
	Packetserver_clients[connectedclient].PPP_packetstartsent = 0; //Packet hasn't been started yet!
}

//srcaddr should be 12 bytes in length.
byte sendIPXechoreply(sword connectedclient, PPP_Stream *echodata, PPP_Stream *srcaddr)
{
	byte datab;
	byte result;
	MODEM_PACKETBUFFER response;
	ETHERNETHEADER ppptransmitheader;
	uint_32 skipdatacounter;
	//Now, construct the ethernet header!
	memcpy(&ppptransmitheader.src, &maclocal, 6); //From us!
	ppptransmitheader.dst[0] = 0xFF;
	ppptransmitheader.dst[1] = 0xFF;
	ppptransmitheader.dst[2] = 0xFF;
	ppptransmitheader.dst[3] = 0xFF;
	ppptransmitheader.dst[4] = 0xFF;
	ppptransmitheader.dst[5] = 0xFF; //To a broadcast!
	ppptransmitheader.type = SDL_SwapBE16(0x8137); //We're an IPX packet!

	memset(&response,0,sizeof(response)); //Clear the response to start filling it!

	for (skipdatacounter = 0; skipdatacounter < 14; ++skipdatacounter)
	{
		if (!packetServerAddPacketBufferQueue(&response, 0)) //Start making room for the header!
		{
			goto ppp_finishpacketbufferqueue_echo; //Keep pending!
		}
	}

	memcpy(&response.buffer[0], ppptransmitheader.data, sizeof(ppptransmitheader.data)); //The ethernet header!
	//Now, create the entire packet as the content for the IPX packet!
	//Header fields
	if (!packetServerAddPacketBufferQueueBE16(&response, 0xFFFF)) //Checksum!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	if (!packetServerAddPacketBufferQueueBE16(&response, PPP_streamdataleft(echodata)+30)) //Length!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	if (!packetServerAddPacketBufferQueue(&response, 0)) //Control!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	if (!packetServerAddPacketBufferQueue(&response, 0x2)) //Echo!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}

	//Now, the destination address, which is the sender of the original request packet!
	for (skipdatacounter = 0; skipdatacounter < 4; ++skipdatacounter)
	{
		if (PPP_consumeStream(srcaddr, &datab)) //The information field itself follows!
		{
			if (!packetServerAddPacketBufferQueue(&response, datab))
			{
				goto ppp_finishpacketbufferqueue_echo;
			}
		}
		else
		{
			goto ppp_finishpacketbufferqueue_echo;
		}
	}
	for (skipdatacounter = 0; skipdatacounter < 6; ++skipdatacounter)
	{
		if (PPP_consumeStream(srcaddr, &datab)) //The information field itself follows!
		{
			if (!packetServerAddPacketBufferQueue(&response, datab))
			{
				goto ppp_finishpacketbufferqueue_echo;
			}
		}
		else
		{
			goto ppp_finishpacketbufferqueue_echo;
		}
	}
	if (!packetServerAddPacketBufferQueueBE16(&response, 0x2)) //Socket!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	//Now, the source address, which is our client address for the connected client!
	for (skipdatacounter = 0; skipdatacounter < 4; ++skipdatacounter)
	{
		if (!packetServerAddPacketBufferQueue(&response, Packetserver_clients[connectedclient].ipxcp_networknumber[0][skipdatacounter])) //Our network number!
		{
			goto ppp_finishpacketbufferqueue_echo; //Keep pending!
		}
	}
	for (skipdatacounter = 0; skipdatacounter < 6; ++skipdatacounter)
	{
		if (!packetServerAddPacketBufferQueue(&response, Packetserver_clients[connectedclient].ipxcp_nodenumber[0][skipdatacounter])) //Our network number!
		{
			goto ppp_finishpacketbufferqueue_echo; //Keep pending!
		}
	}
	if (!packetServerAddPacketBufferQueueBE16(&response, 0x2)) //Socket!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	//This is followed by the data for from the echo packet!
	for (; PPP_consumeStream(echodata, &datab);) //The information field itself follows!
	{
		if (!packetServerAddPacketBufferQueue(&response, datab))
		{
			goto ppp_finishpacketbufferqueue_echo;
		}
	}
	//End of IPX packet creation.

	//Now, the packet we've stored has become the packet to send!
	sendpkt_pcap(response.buffer, response.length); //Send the response on the network!
	result = 1; //Successfully sent!
	goto ppp_finishpacketbufferqueue2_echo;
	ppp_finishpacketbufferqueue_echo: //An error occurred during the response?
	result = 0; //Keep pending until we can properly handle it!
	ppp_finishpacketbufferqueue2_echo:
	packetServerFreePacketBufferQueue(&response); //Free the queued response!
	return result; //Give the result!
}

//Send an IPX echo request to the network for all other existing clients to apply.
byte sendIPXechorequest(sword connectedclient)
{
	byte result;
	MODEM_PACKETBUFFER response;
	ETHERNETHEADER ppptransmitheader;
	uint_32 skipdatacounter;
	//Now, construct the ethernet header!
	memcpy(&ppptransmitheader.src, &maclocal, 6); //From us!
	ppptransmitheader.dst[0] = 0xFF;
	ppptransmitheader.dst[1] = 0xFF;
	ppptransmitheader.dst[2] = 0xFF;
	ppptransmitheader.dst[3] = 0xFF;
	ppptransmitheader.dst[4] = 0xFF;
	ppptransmitheader.dst[5] = 0xFF; //To a broadcast!
	ppptransmitheader.type = SDL_SwapBE16(0x8137); //We're an IPX packet!

	memset(&response,0,sizeof(response)); //Clear the response to start filling it!

	for (skipdatacounter = 0; skipdatacounter < 14; ++skipdatacounter)
	{
		if (!packetServerAddPacketBufferQueue(&response, 0)) //Start making room for the header!
		{
			goto ppp_finishpacketbufferqueue_echo; //Keep pending!
		}
	}

	memcpy(&response.buffer[0], ppptransmitheader.data, sizeof(ppptransmitheader.data)); //The ethernet header!
	//Now, create the entire packet as the content for the IPX packet!
	//Header fields
	if (!packetServerAddPacketBufferQueueBE16(&response, 0xFFFF)) //Checksum!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	if (!packetServerAddPacketBufferQueueBE16(&response, 30)) //Length!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	if (!packetServerAddPacketBufferQueue(&response, 0)) //Control!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	if (!packetServerAddPacketBufferQueue(&response, 0x2)) //Echo!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}

	//Now, the destination address, which is the sender of the original request packet!
	for (skipdatacounter = 0; skipdatacounter < 4; ++skipdatacounter)
	{
		if (!packetServerAddPacketBufferQueue(&response, Packetserver_clients[connectedclient].ipxcp_networknumber[0][skipdatacounter]))
		{
			goto ppp_finishpacketbufferqueue_echo;
		}
	}
	for (skipdatacounter = 0; skipdatacounter < 6; ++skipdatacounter)
	{
		if (!packetServerAddPacketBufferQueue(&response, 0xFF)) //Specified address FFFFFFFF port FFFF!
		{
			goto ppp_finishpacketbufferqueue_echo;
		}
	}
	if (!packetServerAddPacketBufferQueueBE16(&response, 0x2)) //Socket!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	//Now, the source address, which is our client address for the connected client!
	for (skipdatacounter = 0; skipdatacounter < 4; ++skipdatacounter)
	{
		if (!packetServerAddPacketBufferQueue(&response, Packetserver_clients[connectedclient].ipxcp_networknumber[0][skipdatacounter])) //Our network number!
		{
			goto ppp_finishpacketbufferqueue_echo; //Keep pending!
		}
	}
	for (skipdatacounter = 0; skipdatacounter < 6; ++skipdatacounter)
	{
		if (!packetServerAddPacketBufferQueue(&response, ipxnegotiationnodeaddr[skipdatacounter])) //Our node number to send back to!
		{
			goto ppp_finishpacketbufferqueue_echo; //Keep pending!
		}
	}
	if (!packetServerAddPacketBufferQueueBE16(&response, 0x2)) //Socket!
	{
		goto ppp_finishpacketbufferqueue_echo; //Keep pending!
	}
	//This is followed by the data for from the echo packet!
	//Don't need to send any data to echo back, as this isn't used for this case.
	//End of IPX packet creation.

	//Now, the packet we've stored has become the packet to send!
	sendpkt_pcap(response.buffer, response.length); //Send the response on the network!
	result = 1; //Successfully sent!
	goto ppp_finishpacketbufferqueue2_echo;
ppp_finishpacketbufferqueue_echo: //An error occurred during the response?
	result = 0; //Keep pending until we can properly handle it!
ppp_finishpacketbufferqueue2_echo:
	packetServerFreePacketBufferQueue(&response); //Free the queued response!
	return result; //Give the result!
}

//result: 0: success, 1: error
byte PPP_addPPPheader(sbyte connectedclient, MODEM_PACKETBUFFER* response, byte allowheadercompression, word protocol)
{
	//Don't compress the header yet, since it's still negotiating!
	if (!(Packetserver_clients[connectedclient].PPP_headercompressed && allowheadercompression)) //Header isn't compressed?
	{
		if (!packetServerAddPacketBufferQueue(response, 0xFF)) //Start of PPP header!
		{
			return 1; //Finish up!
		}
		if (!packetServerAddPacketBufferQueue(response, 0x03)) //Start of PPP header!
		{
			return 1; //Finish up!
		}
	}
	if (!packetServerAddPacketBufferQueueBE16(response, protocol)) //The protocol!
	{
		return 1; //Finish up!
	}
	return 0; //Success!
}

//result: 0: success, 1: error
byte PPP_addLCPNCPResponseHeader(sbyte connectedclient, MODEM_PACKETBUFFER* response, byte allowheadercompression, word protocol, byte responsetype, byte common_IdentifierField, word contentlength)
{
	if (PPP_addPPPheader(connectedclient, response, allowheadercompression, protocol))
	{
		return 1; //Finish up!
	}
	//Request-Ack header!
	if (!packetServerAddPacketBufferQueue(response, responsetype)) //Response type!
	{
		return 1; //Finish up!
	}
	if (!packetServerAddPacketBufferQueue(response, common_IdentifierField)) //Identifier!
	{
		return 1; //Finish up!
	}
	if (!packetServerAddPacketBufferQueueBE16(response, contentlength + 4)) //How much data follows!
	{
		return 1; //Finish up!
	}
	return 0; //Success!
}

//result: 0: success, 1: error
byte PPP_addFCS(MODEM_PACKETBUFFER* response)
{
	word checksumfield;
	//Calculate and add the checksum field!
	checksumfield = PPP_calcFCS(response->buffer, response->length, 1); //The checksum field!
	if (!packetServerAddPacketBufferQueueBE16(response, checksumfield)) //Checksum failure?
	{
		return 1;
	}
	return 0;
}

//result: 1 on success, 0 on pending.
byte PPP_parseSentPacketFromClient(sword connectedclient, byte handleTransmit)
{
	MODEM_PACKETBUFFER pppNakRejectFields;
	byte result; //The result for this function!
	MODEM_PACKETBUFFER response, pppNakFields, pppRejectFields; //The normal response and Nak fields/Reject fields that are queued!
	MODEM_PACKETBUFFER LCP_requestFields; //Request fields!
	word checksum, checksumfield;
	PPP_Stream pppstream, pppstreambackup, checksumppp, pppstream_informationfield, pppstream_requestfield /*, pppstream_optionfield*/;
	byte datab; //byte data from the stream!
	word dataw; //word data from the stream!
	byte data4[4]; //4-byte data!
	byte data6[6]; //6-byte data!
	word protocol; //The used protocol!
	//Header at the start of the info field!
	byte common_CodeField; //Code field!
	byte common_IdentifierField; //Identifier field!
	word common_LengthField; //Length field!
	byte common_TypeField; //Type field
	byte common_OptionLengthField; //Option Length field!
	byte request_NakRejectpendingMRU; //Pending MTU field for the request!
	word request_pendingMRU; //Pending MTU field for the request!
	byte request_pendingProtocolFieldCompression; //Default: no protocol field compression!
	byte request_pendingAddressAndControlFieldCompression; //Default: no address-and-control-field compression!
	byte request_magic_number_used; //Default: none
	byte request_magic_number[4]; //Set magic number
	byte request_asynccontrolcharactermap[4]; //ASync-Control-Character-Map MSB to LSB (Big Endian)!
	byte request_asynccontrolcharactermapspecified; //Default: none
	word request_authenticationprotocol; //Authentication protocol requested!
	byte request_authenticationspecified; //Authentication protocol used!
	uint_32 skipdatacounter;
	byte pap_fieldcounter; //Length of a field until 0 for PAP comparison!
	byte username_length; //Username length for PAP!
	byte password_length; //Password length for PAP!
	byte pap_authenticated; //Is the user authenticated properly?
	byte nacreject_ipxcp;
	byte ipxcp_pendingnetworknumber[4];
	byte ipxcp_pendingnodenumber[6];
	word ipxcp_pendingroutingprotocol;
	ETHERNETHEADER ppptransmitheader;
	if (handleTransmit)
	{
		if (Packetserver_clients[connectedclient].packetserver_transmitlength < (3 + (!Packetserver_clients[connectedclient].PPP_protocolcompressed[0] ? 1U : 0U) + (!Packetserver_clients[connectedclient].PPP_headercompressed[0] ? 2U : 0U))) //Not enough for a full minimal PPP packet (with 1 byte of payload)?
		{
			return 1; //Incorrect packet: discard it!
		}
	}
	memset(&response, 0, sizeof(response)); //Make sure it's ready for usage!
	//TODO: ipxcp nakfields/rejectfields.
	if (Packetserver_clients[connectedclient].ppp_nakfields.buffer || Packetserver_clients[connectedclient].ppp_rejectfields.buffer) //NAK or Reject packet pending?
	{
		//Try to send the NAK fields or Reject fields to the client!
		if (!handleTransmit) //Not transmitting?
		{
			result = 0; //Default: not handled!
		}
		else
		{
			result = 1; //Default: handled!
		}
		nacreject_ipxcp = 0; //Not IPXCP by default!
		if (Packetserver_clients[connectedclient].ppp_nakfields.buffer) //Gotten NAK fields to send?
		{
			memcpy(&pppNakRejectFields, &Packetserver_clients[connectedclient].ppp_nakfields, sizeof(pppNakRejectFields)); //Which one to use!
			common_CodeField = 3; //NAK!
			common_IdentifierField = Packetserver_clients[connectedclient].ppp_nakfields_identifier; //The identifier!
		}
		else if (Packetserver_clients[connectedclient].ppp_nakfields_ipxcp.buffer) //Gotten NAK fields to send?
		{
			memcpy(&pppNakRejectFields, &Packetserver_clients[connectedclient].ppp_nakfields_ipxcp, sizeof(pppNakRejectFields)); //Which one to use!
			common_CodeField = 3; //NAK!
			common_IdentifierField = Packetserver_clients[connectedclient].ppp_nakfields_ipxcp_identifier; //The identifier!
			nacreject_ipxcp = 1; //IPXCP!
		}
		else if (Packetserver_clients[connectedclient].ppp_rejectfields.buffer) //Gotten Reject fields to send?
		{
			memcpy(&pppNakRejectFields, &Packetserver_clients[connectedclient].ppp_rejectfields, sizeof(pppNakRejectFields)); //Which one to use!
			common_CodeField = 4; //Reject!
			common_IdentifierField = Packetserver_clients[connectedclient].ppp_rejectfields_identifier; //The identifier!
		}
		else
		{
			memcpy(&pppNakRejectFields, &Packetserver_clients[connectedclient].ppp_rejectfields_ipxcp, sizeof(pppNakRejectFields)); //Which one to use!
			common_CodeField = 4; //Reject!
			common_IdentifierField = Packetserver_clients[connectedclient].ppp_rejectfields_ipxcp_identifier; //The identifier!
			nacreject_ipxcp = 1; //IPXCP!
		}

		createPPPstream(&pppstream, &pppNakRejectFields.buffer[0], pppNakRejectFields.length); //Create a stream object for us to use, which goes until the end of the payload!

		//Send a Reject/NAK packet to the client!
		memset(&response, 0, sizeof(response)); //Init the response!
		if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, nacreject_ipxcp?0x802B:0xC021, common_CodeField, common_IdentifierField, PPP_streamdataleft(&pppstream)))
		{
			goto ppp_finishpacketbufferqueueNAKReject;
		}
		//Now, the rejected packet itself!
		for (; PPP_consumeStream(&pppstream, &datab);) //The data field itself follows!
		{
			if (!packetServerAddPacketBufferQueue(&response, datab))
			{
				memset(&pppNakRejectFields, 0, sizeof(pppNakRejectFields)); //Abort!
				goto ppp_finishpacketbufferqueueNAKReject;
			}
		}
		//Calculate and add the checksum field!
		if (PPP_addFCS(&response))
		{
			goto ppp_finishpacketbufferqueueNAKReject;
		}

		//Packet is fully built. Now send it!
		if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
		{
			goto ppp_finishpacketbufferqueueNAKReject; //Keep pending!
		}
		if (response.buffer) //Any response to give?
		{
			memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
			ppp_responseforuser(connectedclient); //A response is ready!
			memset(&response, 0, sizeof(response)); //Parsed!
			if (common_CodeField == 3) //NAK?
			{
				if (nacreject_ipxcp) //IPXCP?
				{
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].ppp_nakfields_ipxcp); //Free the queued response!
				}
				else //LCP?
				{
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].ppp_nakfields); //Free the queued response!
				}
			}
			else //Reject?
			{
				if (nacreject_ipxcp) //IPXCP?
				{
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].ppp_rejectfields_ipxcp); //Free the queued response!
				}
				else //LCP?
				{
					packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].ppp_rejectfields); //Free the queued response!
				}
			}
			if (!handleTransmit) //Not performing an transmit?
			{
				result = 1; //OK, handled!
			}
			else
			{
				result = 0; //Keep pending!
			}
		}
		goto ppp_finishcorrectpacketbufferqueueNAKReject; //Success!
	ppp_finishpacketbufferqueueNAKReject: //An error occurred during the response?
		packetServerFreePacketBufferQueue(&response); //Free the queued response!
		//Don't touch the NakReject field, as this is still pending!
	ppp_finishcorrectpacketbufferqueueNAKReject: //Correctly finished!
		return result; //Keep pending, is selected!
	}
	else if ((!handleTransmit) && (!Packetserver_clients[connectedclient].ppp_LCPstatus[1])) //Not handling a transmitting of anything atm and LCP for the server-client is down?
	{
		//Use a simple nanosecond timer to determine if we're to send a 
		if (getnspassed_k(&Packetserver_clients[connectedclient].ppp_serverLCPrequesttimer) >= ((!Packetserver_clients[connectedclient].ppp_serverLCPstatus)?3000000000.0f:500000000.0f)) //Starting it's timing every interval (first 3 seconds, then half a second)!
		{
			getnspassed(&Packetserver_clients[connectedclient].ppp_serverLCPrequesttimer); //Restart timing!
		}
		else
		{
			goto donthandleServerPPPLCPyet; //Don't handle the sending of a request from the server yet, because we're still timing!
		}
		if (!Packetserver_clients[connectedclient].ppp_serverLCPstatus) //Initializing?
		{
			retryServerLCPnegotiation:
			Packetserver_clients[connectedclient].ppp_serverLCPidentifier = 0; //Init!
			Packetserver_clients[connectedclient].ppp_serverLCPstatus = 1; //Have initialized!
			Packetserver_clients[connectedclient].ppp_serverLCP_haveAddressAndControlFieldCompression = Packetserver_clients[connectedclient].ppp_serverLCP_haveMRU = Packetserver_clients[connectedclient].ppp_serverLCP_haveMagicNumber = Packetserver_clients[connectedclient].ppp_serverLCP_haveProtocolFieldCompression = Packetserver_clients[connectedclient].ppp_serverLCP_haveAsyncControlCharacterMap = 1; //Default by trying all!
			Packetserver_clients[connectedclient].ppp_serverLCP_pendingMRU = 1500; //Default!
			Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber[0] = 0xFF; //Default!
			Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber[1] = 0xFF; //Default!
			Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber[2] = 0xFF; //Default!
			Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber[3] = 0xFF; //Default!
			Packetserver_clients[connectedclient].ppp_serverLCP_haveAsyncControlCharacterMap = 1;
			Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap[0] = Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap[1] = Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap[2] = Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap[3] = 0; //Default!
		}
		else if (Packetserver_clients[connectedclient].ppp_serverLCPstatus>1) //Resetting?
		{
			//Otherwise, it's a retry!
			goto retryServerLCPnegotiation;
		}
		result = 1; //Default: handled!
		//Now, formulate a request!
		Packetserver_clients[connectedclient].ppp_servercurrentLCPidentifier = Packetserver_clients[connectedclient].ppp_serverLCPidentifier; //Load the identifier to try!
		memset(&LCP_requestFields, 0, sizeof(LCP_requestFields)); //Make sure it's ready for usage!
		//case 1: //Maximum Receive Unit
			if (Packetserver_clients[connectedclient].ppp_serverLCP_haveMRU) //Required?
			{
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 0x01)) //Request it!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 4)) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueueBE16(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingMRU)) //Requested data!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
			}
			//Field is OK!
		//case 7: //Protocol Field Compression
			if (Packetserver_clients[connectedclient].ppp_serverLCP_haveProtocolFieldCompression) //To request?
			{
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 0x07)) //NAK it!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 2)) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
			}
		//case 8: //Address-And-Control-Field-Compression
			if (Packetserver_clients[connectedclient].ppp_serverLCP_haveAddressAndControlFieldCompression) //To request?
			{
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 0x08)) //NAK it!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 2)) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
			}
			request_pendingAddressAndControlFieldCompression = 1; //Set the request!
		//case 5: //Magic Number
			if (Packetserver_clients[connectedclient].ppp_serverLCP_haveMagicNumber) //To request?
			{
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 0x05)) //NAK it!
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 6)) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber[0])) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber[1])) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber[2])) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber[3])) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
			}
		//case 3: //Authentication Protocol
			/*
			if (common_OptionLengthField != 4) //Unsupported length?
			{
			invalidauthenticationprotocol:
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 0x03)) //NAK it!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 4)) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueueBE16(&LCP_requestFields, 0xC023)) //PAP!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				goto performskipdata_lcp; //Skip the data please!
			}
			request_authenticationspecified = 1; //Request that authentication be used!
			break;
			*/
		//case 2: //ASync-Control-Character-Map
			if (Packetserver_clients[connectedclient].ppp_serverLCP_haveAsyncControlCharacterMap) //To request?
			{
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 0x02)) //NAK it!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, 6)) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap[0])) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap[1])) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap[2])) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
				if (!packetServerAddPacketBufferQueue(&LCP_requestFields, Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap[3])) //Correct length!
				{
					goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
				}
			}

		createPPPstream(&pppstream, LCP_requestFields.buffer, LCP_requestFields.length); //Create a stream object for us to use, which goes until the end of the payload!
		if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 0, 0xC021, 0x01, Packetserver_clients[connectedclient].ppp_serverLCPidentifier, PPP_streamdataleft(&pppstream))) //Configure-Request
		{
			goto ppp_finishpacketbufferqueue; //Finish up!
		}

		for (; PPP_streamdataleft(&pppstream);) //Data left?
		{
			if (!PPP_consumeStream(&pppstream, &datab))
			{
				goto ppp_finishpacketbufferqueue_lcp; //Incorrect packet: discard it!
			}
			if (!packetServerAddPacketBufferQueue(&response, datab)) //Add it!
			{
				goto ppp_finishpacketbufferqueue_lcp; //Finish up!
			}
		}

		//Calculate and add the checksum field!
		if (PPP_addFCS(&response))
		{
			goto ppp_finishpacketbufferqueue;
		}

		//Packet is fully built. Now send it!
		if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
		{
			goto ppp_finishpacketbufferqueue_lcp; //Keep pending!
		}
		if (response.buffer) //Any response to give?
		{
			memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
			ppp_responseforuser(connectedclient); //A response is ready!
			memset(&response, 0, sizeof(response)); //Parsed!
		}
		goto ppp_finishpacketbufferqueue2_lcp; //Success!
	ppp_finishpacketbufferqueue_lcp: //An error occurred during the response?
		result = 0; //Keep pending until we can properly handle it!
	ppp_finishpacketbufferqueue2_lcp:
		packetServerFreePacketBufferQueue(&LCP_requestFields); //Free the queued response!
		packetServerFreePacketBufferQueue(&response); //Free the queued response!
		packetServerFreePacketBufferQueue(&pppNakFields); //Free the queued response!
		packetServerFreePacketBufferQueue(&pppRejectFields); //Free the queued response!
		return result; //Give the correct result!
	}
	donthandleServerPPPLCPyet: //Don't handle PPP LCP from server yet?
	if (!handleTransmit) return 1; //Don't do anything more when not handling a transmit!
	createPPPstream(&pppstream, &Packetserver_clients[connectedclient].packetserver_transmitbuffer[0], Packetserver_clients[connectedclient].packetserver_transmitlength-2); //Create a stream object for us to use, which goes until the end of the payload!
	createPPPstream(&checksumppp, &Packetserver_clients[connectedclient].packetserver_transmitbuffer[Packetserver_clients[connectedclient].packetserver_transmitlength - 2], 2); //Create a stream object for us to use for the checksum!
	memcpy(&pppstreambackup, &pppstream, sizeof(pppstream)); //Backup for checking again!
	if (!Packetserver_clients[connectedclient].PPP_headercompressed[0]) //Header present?
	{
		if (!PPP_consumeStream(&pppstream, &datab))
		{
			return 1; //incorrect packet: discard it!
		}
		if (datab != 0xFF) //Invalid address?
		{
			return 1; //incorret packet: discard it!
		}
		if (!PPP_consumeStream(&pppstream, &datab))
		{
			return 1; //incorrect packet: discard it!
		}
		if (datab != 0x03) //Invalid control?
		{
			return 1; //incorret packet: discard it!
		}
	}
	else //Header MIGHT be compressed?
	{
		if (!PPP_consumeStreamBE16(&pppstream, &dataw))
		{
			return 1; //Incorrect packet: discard it!
		}
		if (dataw != 0xFF03) //The first two bytes are not 0xFF and 0x03? It's an compressed header instead!
		{
			memcpy(&pppstream, &pppstreambackup, sizeof(pppstream)); //Return the stream to it's proper start, being compressed away!
		}
	}
	//Now, the packet is at the protocol byte/word, so parse it!
	if (!PPP_consumeStream(&pppstream, &datab))
	{
		return 1; //incorrect packet: discard it!
	}
	dataw = (word)datab; //Store First byte, in little-endian!
	if (((datab & 1)==0) || (!Packetserver_clients[connectedclient].PPP_protocolcompressed[0])) //2-byte protocol?
	{
		if (!PPP_consumeStream(&pppstream, &datab)) //Second byte!
		{
			return 1; //Incorrect packet: discard it!
		}
		dataw = (datab | (dataw<<8)); //Second byte of the protocol!
	}
	protocol = dataw; //The used protocol in the header, if it's valid!
	if (!PPP_peekStream(&pppstream, &datab)) //Reached end of stream (no payload)?
	{
		return 1; //Incorrect packet: discard it!
	}
	//Otherwise, it's a 1-byte protocol!
	//It might be a valid packet if we got here! Perform the checksum first to check!
	if (!PPP_consumeStreamBE16(&checksumppp, &checksumfield)) //Gotten the checksum from the packet?
	{
		return 1; //Incorrect packet: discard it!
	}
	checksum = PPP_calcFCS(&Packetserver_clients[connectedclient].packetserver_transmitbuffer[0], Packetserver_clients[connectedclient].packetserver_transmitlength, 0); //Calculate the checksum!
	if (checksum != PPP_GOODFCS) //Checksum error?
	{
		return 1; //Incorrect packet: discard it!
	}
	memcpy(&pppstream_informationfield, &pppstream, sizeof(pppstream)); //The information field that's used, backed up!
	//Now, the PPPstream contains the packet information field, which is the payload. The data has been checked out and is now ready for processing, according to the protocol!
	result = 1; //Default result: finished up!
	memset(&pppNakFields, 0, sizeof(pppNakFields)); //Init to not used!
	memset(&pppRejectFields, 0, sizeof(pppRejectFields)); //Init to not used!
	switch (protocol) //What protocol is used?
	{
	case 0x0001: //Padding protocol?
		//NOP!
		break;
	case 0xC021: //LCP?
		if (!PPP_consumeStream(&pppstream, &common_CodeField)) //Code couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (!PPP_consumeStream(&pppstream, &common_IdentifierField)) //Identifier couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (!PPP_consumeStreamBE16(&pppstream, &common_LengthField)) //Length couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (common_LengthField < 4) //Not enough data?
		{
			return 1; //Incorrect packet: discard it!
		}
		switch (common_CodeField) //What operation code?
		{
		case 1: //Configure-Request
			if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField,4)-4)) //Not enough room for the data?
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			request_pendingMRU = 1500; //Default MTU value to use!
			request_pendingProtocolFieldCompression = 0; //Default: no protocol field compression!
			request_pendingAddressAndControlFieldCompression = 0; //Default: no address-and-control-field compression!
			memset(&request_magic_number, 0, sizeof(request_magic_number)); //Default: none
			request_magic_number_used = 0; //Default: not used!
			request_authenticationspecified = 0; //Default: not used!
			request_asynccontrolcharactermap[0] = request_asynccontrolcharactermap[1] = request_asynccontrolcharactermap[2] = request_asynccontrolcharactermap[3] = 0xFF; //All ones by default!

			//Now, start parsing the options for the connection!
			for (; PPP_peekStream(&pppstream_requestfield, &common_TypeField);) //Gotten a new option to parse?
			{
				if (!PPP_consumeStream(&pppstream_requestfield, &common_TypeField))
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				if (!PPP_consumeStream(&pppstream_requestfield, &common_OptionLengthField))
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				if (PPP_streamdataleft(&pppstream_requestfield) < (MAX(common_OptionLengthField,2U)-2U)) //Not enough room left for the option data?
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				switch (common_TypeField) //What type is specified for the option?
				{
				case 1: //Maximum Receive Unit
					if (common_OptionLengthField != 4) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 4)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueueBE16(&pppNakFields, 1500)) //Correct data!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcp; //Skip the data please!
					}
					if (!PPP_consumeStreamBE16(&pppstream_requestfield, &request_pendingMRU)) //Pending MRU field!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					//Field is OK!
					break;
				case 7: //Protocol Field Compression
					if (common_OptionLengthField != 2) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 2)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcp; //Skip the data please!
					}
					request_pendingProtocolFieldCompression = 1; //Set the request!
					break;
				case 8: //Address-And-Control-Field-Compression
					if (common_OptionLengthField != 2) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 2)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcp; //Skip the data please!
					}
					request_pendingAddressAndControlFieldCompression = 1; //Set the request!
					break;
				case 5: //Magic Number
					if (common_OptionLengthField != 6) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 6)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcp; //Skip the data please!
					}
					request_magic_number_used = 1; //Set the request!
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[0])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[1])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[2])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[3])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					break;
				case 3: //Authentication Protocol
					if (common_OptionLengthField != 4) //Unsupported length?
					{
						invalidauthenticationprotocol:
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 4)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueueBE16(&pppNakFields, 0xC023)) //PAP!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcp; //Skip the data please!
					}
					request_magic_number_used = 1; //Set the request!
					if (!PPP_consumeStreamBE16(&pppstream_requestfield, &request_authenticationprotocol)) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (request_authenticationprotocol != 0xC023) //Not a supported protocol?
					{
						goto invalidauthenticationprotocol; //Count as invalid!
					}
					request_authenticationspecified = 1; //Request that authentication be used!
					break;
				case 2: //ASync-Control-Character-Map
					if (common_OptionLengthField != 6) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 6)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcp; //Skip the data please!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[0])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[1])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[2])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[3])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					break;
				case 4: //Quality protocol
				default: //Unknown option?
					if (!packetServerAddPacketBufferQueue(&pppRejectFields, common_TypeField)) //NAK it!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					if (!packetServerAddPacketBufferQueue(&pppRejectFields, 2)) //Correct length!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					performskipdata_lcp:
					if (common_OptionLengthField >= 2) //Enough length to skip?
					{
						skipdatacounter = common_OptionLengthField - 2; //How much to skip!
						for (; skipdatacounter;) //Skip it!
						{
							if (!PPP_consumeStream(&pppstream_requestfield, &datab)) //Failed to consume properly?
							{
								goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
							}
							--skipdatacounter;
						}
					}
					else //Malformed parameter!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					break;
				}
			}
			//TODO: Finish parsing properly
			if (pppNakFields.buffer || pppRejectFields.buffer) //NAK or Rejected any fields? Then don't process to the connected phase!
			{
				memcpy(&Packetserver_clients[connectedclient].ppp_nakfields, &pppNakFields, sizeof(pppNakFields)); //Give the response to the client!
				Packetserver_clients[connectedclient].ppp_nakfields_identifier = common_IdentifierField; //Identifier!
				memcpy(&Packetserver_clients[connectedclient].ppp_rejectfields, &pppRejectFields, sizeof(pppRejectFields)); //Give the response to the client!
				Packetserver_clients[connectedclient].ppp_rejectfields_identifier = common_IdentifierField; //Identifier!
				memset(&pppNakFields, 0, sizeof(pppNakFields)); //Queued!
				memset(&pppRejectFields, 0, sizeof(pppRejectFields)); //Queued!
				result = 1; //Success!
			}
			else //OK! All parameters are fine!
			{
				//Apply the parameters to the session and send back an request-ACK!
				memset(&response, 0, sizeof(response)); //Init the response!
				//Build the PPP header first!
				//Don't compress the header yet, since it's still negotiating!
				if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField, 4) - 4)) //Not enough room for the data?
				{
					goto ppp_finishpacketbufferqueue; //Finish up!
				}
				if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 0, protocol, 0x02, common_IdentifierField, PPP_streamdataleft(&pppstream_requestfield)))
				{
					goto ppp_finishpacketbufferqueue; //Finish up!
				}
				for (; PPP_streamdataleft(&pppstream_requestfield);) //Data left?
				{
					if (!PPP_consumeStream(&pppstream_requestfield, &datab))
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					if (!packetServerAddPacketBufferQueue(&response, datab)) //Add it!
					{
						goto ppp_finishpacketbufferqueue; //Finish up!
					}
				}
				//Calculate and add the checksum field!
				if (PPP_addFCS(&response))
				{
					goto ppp_finishpacketbufferqueue;
				}
				//Packet is fully built. Now send it!
				if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
				{
					goto ppp_finishpacketbufferqueue; //Keep pending!
				}
				if (response.buffer) //Any response to give?
				{
					memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
					ppp_responseforuser(connectedclient); //A response is ready!
					memset(&response, 0, sizeof(response)); //Parsed!
					//Now, apply the request properly!
					Packetserver_clients[connectedclient].ppp_LCPstatus[0] = 1; //Open!
					Packetserver_clients[connectedclient].PPP_MRU[0] = request_pendingMRU; //MRU!
					Packetserver_clients[connectedclient].PPP_headercompressed[0] = request_pendingAddressAndControlFieldCompression; //Header compression!
					Packetserver_clients[connectedclient].PPP_protocolcompressed[0] = request_pendingProtocolFieldCompression; //Protocol compressed!
					Packetserver_clients[connectedclient].asynccontrolcharactermap[0] = SDL_SwapBE32((request_asynccontrolcharactermap[0]|(request_asynccontrolcharactermap[1]<<8)|(request_asynccontrolcharactermap[2]<<16)|(request_asynccontrolcharactermap[3]<<24)));
					memcpy(&Packetserver_clients[connectedclient].magic_number[0], &request_magic_number, sizeof(request_magic_number)); //Magic number
					Packetserver_clients[connectedclient].have_magic_number[0] = request_magic_number_used; //Use magic number?
					if (request_authenticationspecified) //Authentication specified?
					{
						Packetserver_clients[connectedclient].ppp_PAPstatus[0] = 0; //Not Authenticated yet!
					}
					else
					{
						Packetserver_clients[connectedclient].ppp_PAPstatus[0] = 1; //Authenticated automatically!
					}
					Packetserver_clients[connectedclient].ppp_IPXCPstatus[0] = 0; //Closed!
					Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 0; //No negotation yet!
				}
				result = 1; //Success!
			}
			goto ppp_finishpacketbufferqueue2; //Finish up!
			break;
		case 5: //Terminate-Request (Request termination of connection)
			//Send a Code-Reject packet to the client!
			memset(&response, 0, sizeof(response)); //Init the response!
			//Build the PPP header first!
			if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, protocol, 0x06, common_IdentifierField, PPP_streamdataleft(&pppstream)))
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			//Now, the rejected packet itself!
			for (; PPP_consumeStream(&pppstream, &datab);) //The data field itself follows!
			{
				if (!packetServerAddPacketBufferQueue(&response, datab))
				{
					goto ppp_finishpacketbufferqueue;
				}
			}
			//Calculate and add the checksum field!
			if (PPP_addFCS(&response))
			{
				goto ppp_finishpacketbufferqueue;
			}
			//Packet is fully built. Now send it!
			if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
			{
				goto ppp_finishpacketbufferqueue; //Keep pending!
			}
			if (response.buffer) //Any response to give?
			{
				memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
				ppp_responseforuser(connectedclient); //A response is ready!
				memset(&response, 0, sizeof(response)); //Parsed!
				//Now, apply the request properly!
				Packetserver_clients[connectedclient].ppp_LCPstatus[0] = 0; //Closed!
				Packetserver_clients[connectedclient].PPP_MRU[0] = 1500; //Default: 1500
				Packetserver_clients[connectedclient].PPP_headercompressed[0] = 0; //Default: uncompressed
				Packetserver_clients[connectedclient].PPP_protocolcompressed[0] = 0; //Default: uncompressed
				Packetserver_clients[connectedclient].have_magic_number[0] = 0; //Default: no magic number yet
			}
			goto ppp_finishpacketbufferqueue2; //Finish up!
			break;
		case 9: //Echo-Request (Request Echo-Reply. Required for an open connection to reply).
			//Send a Code-Reject packet to the client!
			if ((!Packetserver_clients[connectedclient].ppp_LCPstatus) || (!Packetserver_clients[connectedclient].have_magic_number))
			{
				result = 1;
				goto ppp_finishpacketbufferqueue2; //Finish up!
			}
			memset(&response, 0, sizeof(response)); //Init the response!
			if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField, 4) - 4)) //Not enough room for the data?
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, protocol, 0x0A, common_IdentifierField, PPP_streamdataleft(&pppstream_requestfield)))
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			if (Packetserver_clients[connectedclient].have_magic_number) //Magic number set?
			{
				if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[0])) //Length couldn't be read?
				{
					goto ppp_finishpacketbufferqueue2; //Finish up!
				}
				if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[1])) //Length couldn't be read?
				{
					goto ppp_finishpacketbufferqueue2; //Finish up!
				}
				if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[2])) //Length couldn't be read?
				{
					goto ppp_finishpacketbufferqueue2; //Finish up!
				}
				if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[3])) //Length couldn't be read?
				{
					goto ppp_finishpacketbufferqueue2; //Finish up!
				}
				if (memcmp(&request_magic_number, Packetserver_clients[connectedclient].magic_number, sizeof(request_magic_number)) != 0) //Maguc number mismatch?
				{
					result = 1; //Duscard!
					goto ppp_finishpacketbufferqueue2; //Finish up!
				}
				if (!packetServerAddPacketBufferQueue(&response, request_magic_number[0])) //Magic-number option!
				{
					goto ppp_finishpacketbufferqueue; //Finish up!
				}
				if (!packetServerAddPacketBufferQueue(&response, request_magic_number[1])) //Magic-number option!
				{
					goto ppp_finishpacketbufferqueue; //Finish up!
				}
				if (!packetServerAddPacketBufferQueue(&response, request_magic_number[2])) //Magic-number option!
				{
					goto ppp_finishpacketbufferqueue; //Finish up!
				}
				if (!packetServerAddPacketBufferQueue(&response, request_magic_number[3])) //Magic-number option!
				{
					goto ppp_finishpacketbufferqueue; //Finish up!
				}
			}
			else //Magic-number option missing?
			{
				result = 1; //Duscard!
				goto ppp_finishpacketbufferqueue2; //Finish up!
			}
			//Now, the rejected packet itself!
			for (; PPP_consumeStream(&pppstream_requestfield, &datab);) //The data field itself follows!
			{
				if (!packetServerAddPacketBufferQueue(&response, datab))
				{
					goto ppp_finishpacketbufferqueue;
				}
			}
			//Calculate and add the checksum field!
			if (PPP_addFCS(&response))
			{
				goto ppp_finishpacketbufferqueue;
			}
			//Packet is fully built. Now send it!
			if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
			{
				goto ppp_finishpacketbufferqueue; //Keep pending!
			}
			if (response.buffer) //Any response to give?
			{
				memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
				ppp_responseforuser(connectedclient); //A response is ready!
				memset(&response, 0, sizeof(response)); //Parsed!
			}
			goto ppp_finishpacketbufferqueue2; //Finish up!
			break;
		case 2: //Configure-Ack (All options OK)
			if (common_IdentifierField != Packetserver_clients[connectedclient].ppp_servercurrentLCPidentifier) //Identifier mismatch?
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField, 4) - 4)) //Not enough room for the data?
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			request_pendingMRU = 1500; //Default MTU value to use!
			request_pendingProtocolFieldCompression = 0; //Default: no protocol field compression!
			request_pendingAddressAndControlFieldCompression = 0; //Default: no address-and-control-field compression!
			memset(&request_magic_number, 0, sizeof(request_magic_number)); //Default: none
			request_magic_number_used = 0; //Default: not used!
			request_authenticationspecified = 0; //Default: not used!
			request_asynccontrolcharactermap[0] = request_asynccontrolcharactermap[1] = request_asynccontrolcharactermap[2] = request_asynccontrolcharactermap[3] = 0xFF; //All ones by default!

			//Now, start parsing the options for the connection!
			for (; PPP_peekStream(&pppstream_requestfield, &common_TypeField);) //Gotten a new option to parse?
			{
				if (!PPP_consumeStream(&pppstream_requestfield, &common_TypeField))
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				if (!PPP_consumeStream(&pppstream_requestfield, &common_OptionLengthField))
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				if (PPP_streamdataleft(&pppstream_requestfield) < (MAX(common_OptionLengthField, 2U) - 2U)) //Not enough room left for the option data?
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				switch (common_TypeField) //What type is specified for the option?
				{
				case 1: //Maximum Receive Unit
					if (common_OptionLengthField != 4) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 4)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueueBE16(&pppNakFields, 1500)) //Correct data!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpack; //Skip the data please!
					}
					if (!PPP_consumeStreamBE16(&pppstream_requestfield, &request_pendingMRU)) //Pending MRU field!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					//Field is OK!
					break;
				case 7: //Protocol Field Compression
					if (common_OptionLengthField != 2) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 2)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpack; //Skip the data please!
					}
					request_pendingProtocolFieldCompression = 1; //Set the request!
					break;
				case 8: //Address-And-Control-Field-Compression
					if (common_OptionLengthField != 2) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 2)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpack; //Skip the data please!
					}
					request_pendingAddressAndControlFieldCompression = 1; //Set the request!
					break;
				case 5: //Magic Number
					if (common_OptionLengthField != 6) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 6)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpack; //Skip the data please!
					}
					request_magic_number_used = 1; //Set the request!
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[0])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[1])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[2])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[3])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					break;
				case 3: //Authentication Protocol
					if (common_OptionLengthField != 4) //Unsupported length?
					{
					invalidauthenticationprotocol_lcpack:
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 4)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueueBE16(&pppNakFields, 0xC023)) //PAP!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpack; //Skip the data please!
					}
					request_magic_number_used = 1; //Set the request!
					if (!PPP_consumeStreamBE16(&pppstream_requestfield, &request_authenticationprotocol)) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (request_authenticationprotocol != 0xC023) //Not a supported protocol?
					{
						goto invalidauthenticationprotocol_lcpack; //Count as invalid!
					}
					request_authenticationspecified = 1; //Request that authentication be used!
					break;
				case 2: //ASync-Control-Character-Map
					if (common_OptionLengthField != 6) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 6)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpack; //Skip the data please!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[0])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[1])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[2])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[3])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					break;
				case 4: //Quality protocol
				default: //Unknown option?
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					if (!packetServerAddPacketBufferQueue(&pppRejectFields, common_TypeField)) //NAK it!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					if (!packetServerAddPacketBufferQueue(&pppRejectFields, 2)) //Correct length!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
				performskipdata_lcpack:
					if (common_OptionLengthField >= 2) //Enough length to skip?
					{
						skipdatacounter = common_OptionLengthField - 2; //How much to skip!
						for (; skipdatacounter;) //Skip it!
						{
							if (!PPP_consumeStream(&pppstream_requestfield, &datab)) //Failed to consume properly?
							{
								goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
							}
							--skipdatacounter;
						}
					}
					else //Malformed parameter!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					break;
				}
			}

			//TODO: Finish parsing properly
			if (!(pppNakFields.buffer || pppRejectFields.buffer)) //NAK or Rejected any fields? Then don't process to the connected phase!
			{
				result = 1; //Discard it!
			}
			else //OK! All parameters are fine!
			{
				//Apply the parameters to the session and start the connection!
				memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
				ppp_responseforuser(connectedclient); //A response is ready!
				memset(&response, 0, sizeof(response)); //Parsed!
				//Now, apply the request properly!
				Packetserver_clients[connectedclient].ppp_LCPstatus[1] = 1; //Open!
				Packetserver_clients[connectedclient].PPP_MRU[1] = request_pendingMRU; //MRU!
				Packetserver_clients[connectedclient].PPP_headercompressed[1] = request_pendingAddressAndControlFieldCompression; //Header compression!
				Packetserver_clients[connectedclient].PPP_protocolcompressed[1] = request_pendingProtocolFieldCompression; //Protocol compressed!
				Packetserver_clients[connectedclient].asynccontrolcharactermap[1] = SDL_SwapBE32((request_asynccontrolcharactermap[0] | (request_asynccontrolcharactermap[1] << 8) | (request_asynccontrolcharactermap[2] << 16) | (request_asynccontrolcharactermap[3] << 24)));
				memcpy(&Packetserver_clients[connectedclient].magic_number[1], &request_magic_number, sizeof(request_magic_number)); //Magic number
				Packetserver_clients[connectedclient].have_magic_number[1] = request_magic_number_used; //Use magic number?
				if (request_authenticationspecified) //Authentication specified?
				{
					Packetserver_clients[connectedclient].ppp_PAPstatus[1] = 0; //Not Authenticated yet!
				}
				else
				{
					Packetserver_clients[connectedclient].ppp_PAPstatus[1] = 1; //Authenticated automatically!
				}
				Packetserver_clients[connectedclient].ppp_IPXCPstatus[1] = 0; //Closed!
				//Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 0; //No negotation yet!
				Packetserver_clients[connectedclient].ppp_serverLCPstatus = 0; //Reset the status check to try again afterwards if it's reset again!
				result = 1; //Success!
			}
			goto ppp_finishpacketbufferqueue2; //Finish up!
			break;
		case 3: //Configure-Nak (Some options unacceptable)
		case 4: //Configure-Reject (Some options not recognisable or acceptable for negotiation)
			if (common_IdentifierField != Packetserver_clients[connectedclient].ppp_servercurrentLCPidentifier) //Identifier mismatch?
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField, 4) - 4)) //Not enough room for the data?
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			request_NakRejectpendingMRU = 0; //Not used by default!
			request_pendingMRU = 1500; //Default MTU value to use!
			request_pendingProtocolFieldCompression = 0; //Default: no protocol field compression!
			request_pendingAddressAndControlFieldCompression = 0; //Default: no address-and-control-field compression!
			memset(&request_magic_number, 0, sizeof(request_magic_number)); //Default: none
			request_magic_number_used = 0; //Default: not used!
			request_authenticationspecified = 0; //Default: not used!
			request_asynccontrolcharactermap[0] = request_asynccontrolcharactermap[1] = request_asynccontrolcharactermap[2] = request_asynccontrolcharactermap[3] = 0xFF; //All ones by default!
			request_asynccontrolcharactermapspecified = 0; //Default: not used!

			//Now, start parsing the options for the connection!
			for (; PPP_peekStream(&pppstream_requestfield, &common_TypeField);) //Gotten a new option to parse?
			{
				if (!PPP_consumeStream(&pppstream_requestfield, &common_TypeField))
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				if (!PPP_consumeStream(&pppstream_requestfield, &common_OptionLengthField))
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				if (PPP_streamdataleft(&pppstream_requestfield) < (MAX(common_OptionLengthField, 2U) - 2U)) //Not enough room left for the option data?
				{
					goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
				}
				switch (common_TypeField) //What type is specified for the option?
				{
				case 1: //Maximum Receive Unit
					if (common_OptionLengthField != 4) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 4)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueueBE16(&pppNakFields, 1500)) //Correct data!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpnakreject; //Skip the data please!
					}
					if (!PPP_consumeStreamBE16(&pppstream_requestfield, &request_pendingMRU)) //Pending MRU field!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					request_NakRejectpendingMRU = 1; //This was Nak/Rejected!
					//Field is OK!
					break;
				case 7: //Protocol Field Compression
					if (common_OptionLengthField != 2) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 2)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpnakreject; //Skip the data please!
					}
					request_pendingProtocolFieldCompression = 1; //Set the request!
					break;
				case 8: //Address-And-Control-Field-Compression
					if (common_OptionLengthField != 2) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 2)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpnakreject; //Skip the data please!
					}
					request_pendingAddressAndControlFieldCompression = 1; //Set the request!
					break;
				case 5: //Magic Number
					if (common_OptionLengthField != 6) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 6)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpnakreject; //Skip the data please!
					}
					request_magic_number_used = 1; //Set the request!
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[0])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[1])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[2])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_magic_number[3])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					break;
				case 3: //Authentication Protocol
					if (common_OptionLengthField != 4) //Unsupported length?
					{
					invalidauthenticationprotocol_lcpnakreject:
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 4)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueueBE16(&pppNakFields, 0xC023)) //PAP!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpnakreject; //Skip the data please!
					}
					//request_magic_number_used = 1; //Set the request!
					if (!PPP_consumeStreamBE16(&pppstream_requestfield, &request_authenticationprotocol)) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (request_authenticationprotocol != 0xC023) //Not a supported protocol?
					{
						goto invalidauthenticationprotocol_lcpnakreject; //Count as invalid!
					}
					request_authenticationspecified = 1; //Request that authentication be used!
					break;
				case 2: //ASync-Control-Character-Map
					if (common_OptionLengthField != 6) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 6)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0xFF)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
						}
						goto performskipdata_lcpnakreject; //Skip the data please!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[0])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[1])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[2])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &request_asynccontrolcharactermap[3])) //Length couldn't be read?
					{
						result = 1; //Duscard!
						goto ppp_finishpacketbufferqueue2; //Finish up!
					}
					request_asynccontrolcharactermapspecified = 1; //Used!
					break;
				case 4: //Quality protocol
				default: //Unknown option?
					if (!packetServerAddPacketBufferQueue(&pppRejectFields, common_TypeField)) //NAK it!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					if (!packetServerAddPacketBufferQueue(&pppRejectFields, 2)) //Correct length!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
				performskipdata_lcpnakreject:
					if (common_OptionLengthField >= 2) //Enough length to skip?
					{
						skipdatacounter = common_OptionLengthField - 2; //How much to skip!
						for (; skipdatacounter;) //Skip it!
						{
							if (!PPP_consumeStream(&pppstream_requestfield, &datab)) //Failed to consume properly?
							{
								goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
							}
							--skipdatacounter;
						}
					}
					else //Malformed parameter!
					{
						goto ppp_finishpacketbufferqueue; //Incorrect packet: discard it!
					}
					break;
				}
			}
			if ((pppNakFields.length == 0) && (pppRejectFields.length == 0)) //OK to process?
			{
				if (request_NakRejectpendingMRU && (common_CodeField == 4)) //Reject-MRU?
				{
					Packetserver_clients[connectedclient].ppp_serverLCP_haveMRU = 0; //Don't request anymore!
				}
				else if (request_NakRejectpendingMRU) //MRU change requested?
				{
					Packetserver_clients[connectedclient].ppp_serverLCP_pendingMRU = request_pendingMRU; //The request MRU to use!
				}
				if (request_pendingProtocolFieldCompression) //Protocol field compression Nak/Reject?
				{
					Packetserver_clients[connectedclient].ppp_serverLCP_haveProtocolFieldCompression = 0; //Not anymore!
				}
				if (request_pendingAddressAndControlFieldCompression) //Address and Control Field Compression Nak/Reject?
				{
					Packetserver_clients[connectedclient].ppp_serverLCP_haveAddressAndControlFieldCompression = 0; //Not anymore!
				}
				if (request_magic_number_used && (common_CodeField == 4)) //Reject-Magic number?
				{
					Packetserver_clients[connectedclient].ppp_serverLCP_haveMagicNumber = 0; //Not anymore!
				}
				else if (request_magic_number_used) //Magic number requested?
				{
					memcpy(&Packetserver_clients[connectedclient].ppp_serverLCP_pendingMagicNumber, request_magic_number, sizeof(request_magic_number)); //The magic number to use!
				}
				if (request_asynccontrolcharactermapspecified && (common_CodeField == 4)) //Reject-Async control character map?
				{
					Packetserver_clients[connectedclient].ppp_serverLCP_haveAsyncControlCharacterMap = 0; //Not anymore!
				}
				else if (request_asynccontrolcharactermapspecified) //Async control character map requested?
				{
					memcpy(&Packetserver_clients[connectedclient].ppp_serverLCP_pendingASyncControlCharacterMap, request_asynccontrolcharactermap, sizeof(request_asynccontrolcharactermap)); //ASync-Control-Character-Map to use?
				}
			}
			result = 1; //Success!
			goto ppp_finishpacketbufferqueue2; //Finish up!
			break;
		case 11: //Discard-Request
			if (Packetserver_clients[connectedclient].ppp_LCPstatus) //LCP opened?
			{
				//Magic-NUmber is ignored.
				//This packet is fully discarded!
				result = 1; //Simply discard it, not doing anything with this packet!
				goto ppp_finishpacketbufferqueue2; //Simply 
				break;
			}
			//Is LCP is closed, an Code-Reject is issued instead?
		case 6: //Terminate-Ack (Acnowledge termination of connection)
		case 7: //Code-Reject (Code field is rejected because it's unknown)
		case 8: //Protocol-Reject (Protocol field is rejected for an active connection)
		case 10: //Echo-Reply
		default: //Unknown Code field?
			//Send a Code-Reject packet to the client!
			memset(&response, 0, sizeof(response)); //Init the response!
			//Build the PPP header first!
			if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, protocol, 0x07, common_IdentifierField, PPP_streamdataleft(&pppstream_informationfield)))
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			//Now, the rejected packet itself!
			for (; PPP_consumeStream(&pppstream_informationfield,&datab);) //The information field itself follows!
			{
				if (!packetServerAddPacketBufferQueue(&response, datab))
				{
					goto ppp_finishpacketbufferqueue;
				}
			}
			//Calculate and add the checksum field!
			if (PPP_addFCS(&response))
			{
				goto ppp_finishpacketbufferqueue;
			}
			break;
		}
		//Packet is fully built. Now send it!
		if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
		{
			goto ppp_finishpacketbufferqueue; //Keep pending!
		}
		if (response.buffer) //Any response to give?
		{
			memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
			ppp_responseforuser(connectedclient); //A response is ready!
			memset(&response, 0, sizeof(response)); //Parsed!
		}
		goto ppp_finishpacketbufferqueue2; //Success!
		ppp_finishpacketbufferqueue: //An error occurred during the response?
		result = 0; //Keep pending until we can properly handle it!
		ppp_finishpacketbufferqueue2:
		packetServerFreePacketBufferQueue(&response); //Free the queued response!
		packetServerFreePacketBufferQueue(&pppNakFields); //Free the queued response!
		packetServerFreePacketBufferQueue(&pppRejectFields); //Free the queued response!
		break;
	case 0xC023: //PAP?
		if (!Packetserver_clients[connectedclient].ppp_LCPstatus) //LCP is closed?
		{
			goto ppp_invalidprotocol; //Invalid protocol!
		}
		if (!PPP_consumeStream(&pppstream, &common_CodeField)) //Code couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (!PPP_consumeStream(&pppstream, &common_IdentifierField)) //Identifier couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (!PPP_consumeStreamBE16(&pppstream, &common_LengthField)) //Length couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (common_LengthField < 6) //Not enough data?
		{
			return 1; //Incorrect packet: discard it!
		}
		switch (common_CodeField) //What operation code?
		{
		case 1: //Authentication-Request
			if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField, 4) - 4)) //Not enough room for the data?
			{
				goto ppp_finishpacketbufferqueue_pap; //Finish up!
			}

			if (!PPP_consumeStream(&pppstream_requestfield, &username_length))
			{
				goto ppp_finishpacketbufferqueue_pap; //Incorrect packet: discard it!
			}
			pap_authenticated = 1; //Default: authenticated properly!
			//First, the username!
			if (username_length != safe_strlen(Packetserver_clients[connectedclient].packetserver_username, sizeof(Packetserver_clients[connectedclient].packetserver_username))) //Length mismatch?
			{
				pap_authenticated = 0; //Not authenticated!
			}
			for (pap_fieldcounter = 0; pap_fieldcounter < username_length; ++pap_fieldcounter) //Now the username follows (for the specified length)
			{
				if (!PPP_consumeStream(&pppstream_requestfield, &datab)) //Data to compare!
				{
					goto ppp_finishpacketbufferqueue_pap; //Incorrect packet: discard it!
				}
				if (pap_authenticated) //Still valid to compare?
				{
					if (Packetserver_clients[connectedclient].packetserver_username[pap_fieldcounter] != datab) //Mismatch?
					{
						pap_authenticated = 0; //Going to NAK it!
					}
				}
			}
			//Now the password follows (for the specified length)
			if (!PPP_consumeStream(&pppstream_requestfield, &password_length))
			{
				goto ppp_finishpacketbufferqueue_pap; //Incorrect packet: discard it!
			}
			if (password_length != safe_strlen(Packetserver_clients[connectedclient].packetserver_password, sizeof(Packetserver_clients[connectedclient].packetserver_password))) //Length mismatch?
			{
				pap_authenticated = 0; //Not authenticated!
			}
			for (pap_fieldcounter = 0; pap_fieldcounter < username_length; ++pap_fieldcounter) //Now the username follows (for the specified length)
			{
				if (!PPP_consumeStream(&pppstream_requestfield, &datab)) //Data to compare!
				{
					goto ppp_finishpacketbufferqueue_pap; //Incorrect packet: discard it!
				}
				if (pap_authenticated) //Still valid to compare?
				{
					if (Packetserver_clients[connectedclient].packetserver_password[pap_fieldcounter] != datab) //Mismatch?
					{
						pap_authenticated = 0; //Going to NAK it!
					}
				}
			}


			//Apply the parameters to the session and send back an request-ACK/NAK!
			memset(&response, 0, sizeof(response)); //Init the response!
			//Build the PPP header first!
			if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField, 4) - 4)) //Not enough room for the data?
			{
				goto ppp_finishpacketbufferqueue_pap; //Finish up!
			}
			if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, protocol, pap_authenticated ? 0x02 : 0x03, common_IdentifierField, 0)) //Authentication-Ack/Nak. No message
			{
				goto ppp_finishpacketbufferqueue_pap; //Finish up!
			}
			//No message for now!
			//Calculate and add the checksum field!
			if (PPP_addFCS(&response))
			{
				goto ppp_finishpacketbufferqueue_pap;
			}
			//Packet is fully built. Now send it!
			if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
			{
				goto ppp_finishpacketbufferqueue_pap; //Keep pending!
			}
			if (response.buffer) //Any response to give?
			{
				memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
				ppp_responseforuser(connectedclient); //A response is ready!
				memset(&response, 0, sizeof(response)); //Parsed!
				//Now, apply the request properly!
				if (pap_authenticated) //Authenticated?
				{
					Packetserver_clients[connectedclient].ppp_PAPstatus[0] = 1; //Authenticated!
				}
				else
				{
					Packetserver_clients[connectedclient].ppp_PAPstatus[0] = 0; //Not authenticated!
				}
			}
			goto ppp_finishpacketbufferqueue2_pap; //Finish up!
			break;
		default: //Unknown Code field?
			goto ppp_finishpacketbufferqueue2_pap; //Finish up only (NOP)!
			break;
		}
		if (response.buffer) //Any response to give?
		{
			memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
			ppp_responseforuser(connectedclient); //A response is ready!
			memset(&response, 0, sizeof(response)); //Parsed!
		}
		result = 1; //Handled!
		goto ppp_finishpacketbufferqueue2_pap; //Success!
	ppp_finishpacketbufferqueue_pap: //An error occurred during the response?
		result = 0; //Keep pending until we can properly handle it!
	ppp_finishpacketbufferqueue2_pap:
		packetServerFreePacketBufferQueue(&response); //Free the queued response!
		packetServerFreePacketBufferQueue(&pppNakFields); //Free the queued response!
		packetServerFreePacketBufferQueue(&pppRejectFields); //Free the queued response!
		break;
	case 0x802B: //IPXCP?
		if ((!Packetserver_clients[connectedclient].ppp_LCPstatus) || (!Packetserver_clients[connectedclient].ppp_PAPstatus)) //LCP is Closed or PAP isn't authenticated?
		{
			goto ppp_invalidprotocol; //Don't handle!
		}

		if (!PPP_consumeStream(&pppstream, &common_CodeField)) //Code couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (!PPP_consumeStream(&pppstream, &common_IdentifierField)) //Identifier couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (!PPP_consumeStreamBE16(&pppstream, &common_LengthField)) //Length couldn't be read?
		{
			return 1; //Incorrect packet: discard it!
		}
		if (common_LengthField < 4) //Not enough data?
		{
			return 1; //Incorrect packet: discard it!
		}
		switch (common_CodeField) //What operation code?
		{
		case 1: //Configure-Request
			if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField, 4) - 4)) //Not enough room for the data?
			{
				goto ppp_finishpacketbufferqueue_ipxcp; //Finish up!
			}

			memset(&ipxcp_pendingnetworknumber,0,sizeof(ipxcp_pendingnetworknumber)); //Default: none!
			memset(&ipxcp_pendingnodenumber,0,sizeof(ipxcp_pendingnodenumber)); //Node number!
			ipxcp_pendingroutingprotocol = 0; //No routing protocol!

			//Now, start parsing the options for the connection!
			for (; PPP_peekStream(&pppstream_requestfield, &common_TypeField);) //Gotten a new option to parse?
			{
				if (!PPP_consumeStream(&pppstream_requestfield, &common_TypeField))
				{
					goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
				}
				if (!PPP_consumeStream(&pppstream_requestfield, &common_OptionLengthField))
				{
					goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
				}
				if (PPP_streamdataleft(&pppstream_requestfield) < (MAX(common_OptionLengthField, 2U) - 2U)) //Not enough room left for the option data?
				{
					goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
				}
				switch (common_TypeField) //What type is specified for the option?
				{
				case 1: //IPX-Network-Number
					if (common_OptionLengthField != 6) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 6)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						goto performskipdata_ipx; //Skip the data please!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data4[0])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data4[1])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data4[2])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data4[3])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					memcpy(&ipxcp_pendingnetworknumber, &data4, 4); //Set the network number to use!
					//Field is OK!
					break;
				case 2: //IPX-Node-Number
					if (common_OptionLengthField != 8) //Unsupported length?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 8)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						goto performskipdata_ipx; //Skip the data please!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data6[0])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}

					if (!PPP_consumeStream(&pppstream_requestfield, &data6[1])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data6[2])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data6[3])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data6[4])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!PPP_consumeStream(&pppstream_requestfield, &data6[5])) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					memcpy(&ipxcp_pendingnodenumber, &data6, 6); //Set the network number to use!
					//Field is OK!
					break;
				case 4: //IPX-Routing-Protocol
					if (common_OptionLengthField != 4) //Unsupported length?
					{
						ipxcp_unsupportedroutingprotocol: //Unsupported routing protocol?
						if (!packetServerAddPacketBufferQueue(&pppNakFields, common_TypeField)) //NAK it!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 8)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0)) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						goto performskipdata_ipx; //Skip the data please!
					}
					if (!PPP_consumeStreamBE16(&pppstream_requestfield, &dataw)) //Pending Node Number field!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (dataw != 0) //Not supported?
					{
						goto ipxcp_unsupportedroutingprotocol;
					}
					ipxcp_pendingroutingprotocol = dataw; //Set the routing protocol to use!
					//Field is OK!
					break;
					break;
				case 3: //IPX-Compression-Protocol
				case 5: //IPX-Router-Name
				case 6: //IPX-Configuration-Complete
				default: //Unknown option?
					if (!packetServerAddPacketBufferQueue(&pppRejectFields, common_TypeField)) //NAK it!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!packetServerAddPacketBufferQueue(&pppRejectFields, 2)) //Correct length!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					performskipdata_ipx:
					if (common_OptionLengthField >= 2) //Enough length to skip?
					{
						skipdatacounter = common_OptionLengthField - 2; //How much to skip!
						for (; skipdatacounter;) //Skip it!
						{
							if (!PPP_consumeStream(&pppstream_requestfield, &datab)) //Failed to consume properly?
							{
								goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
							}
							--skipdatacounter;
						}
					}
					else //Malformed parameter!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					break;
				}
			}
			//TODO: Finish parsing properly
			if (pppNakFields.buffer || pppRejectFields.buffer) //NAK or Rejected any fields? Then don't process to the connected phase!
			{
				ipxcp_requestfixnodenumber: //Fix network number supplied by authentication!
				memcpy(&Packetserver_clients[connectedclient].ppp_nakfields_ipxcp, &pppNakFields, sizeof(pppNakFields)); //Give the response to the client!
				Packetserver_clients[connectedclient].ppp_nakfields_ipxcp_identifier = common_IdentifierField; //Identifier!
				memcpy(&Packetserver_clients[connectedclient].ppp_rejectfields_ipxcp, &pppRejectFields, sizeof(pppRejectFields)); //Give the response to the client!
				Packetserver_clients[connectedclient].ppp_rejectfields_ipxcp_identifier = common_IdentifierField; //Identifier!
				memset(&pppNakFields, 0, sizeof(pppNakFields)); //Queued!
				memset(&pppRejectFields, 0, sizeof(pppRejectFields)); //Queued!
				result = 1; ///Discard!
			}
			else //OK! All parameters are fine!
			{
				if (Packetserver_clients[connectedclient].ipxcp_negotiationstatus == 0) //Starting negotiation on the parameters?
				{
					if (!memcmp(&ipxcp_pendingnodenumber, &ipxnulladdr, 6)) //Null address?
					{
						Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 2; //NAK it!
					}
					else if (memcmp(&ipxcp_pendingnodenumber, &ipxbroadcastaddr, 6)) //Broadcast address?
					{
						Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 2; //NAK it!
					}
					else if (memcmp(&ipxcp_pendingnodenumber, &ipxnegotiationnodeaddr, 6)) //Negotiation node address?
					{
						Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 2; //NAK it!
					}
					else //Valid address to use? Start validation of existing clients!
					{
						//TODO: Check other clients for pending negotiations! Wait for other clients to complete first!
						memcpy(Packetserver_clients[connectedclient].ipxcp_networknumber, &ipxcp_pendingnetworknumber, sizeof(ipxcp_pendingnetworknumber)); //Network number specified or 0 for none!
						memcpy(Packetserver_clients[connectedclient].ipxcp_nodenumber, &ipxcp_pendingnodenumber, sizeof(ipxcp_pendingnodenumber)); //Node number or 0 for none!
						if (sendIPXechorequest(connectedclient)) //Properly sent an echo request?
						{
							Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 1; //Start negotiating the IPX node number!
							initTicksHolder(&Packetserver_clients[connectedclient].ipxcp_negotiationstatustimer); //Initialize the timer!
							getnspassed(&Packetserver_clients[connectedclient].ipxcp_negotiationstatustimer); //Start the timer now!
						}
						//Otherwise, keep pending!
					}
				}

				if (Packetserver_clients[connectedclient].ipxcp_negotiationstatus == 1) //Timing the timer for negotiating the network/node address?
				{
					if (getnspassed_k(&Packetserver_clients[connectedclient].ipxcp_negotiationstatustimer) >= 1500000000.0f) //Negotiation timeout?
					{
						Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 3; //Timeout reached! No other client responded to the request! Take the network/node address specified! 
					}
				}

				if (Packetserver_clients[connectedclient].ipxcp_negotiationstatus != 3) //Not ready yet?
				{
					if (Packetserver_clients[connectedclient].ipxcp_negotiationstatus == 2) //NAK has been reached?
					{
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 0x02)) //IPX node number!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						incIPXaddr(&ipxcp_pendingnodenumber[0]); //Increase the address to the first next valid address to use!
						if (!packetServerAddPacketBufferQueue(&pppNakFields, 8)) //Correct length!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, ipxcp_pendingnodenumber[0])) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, ipxcp_pendingnodenumber[1])) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, ipxcp_pendingnodenumber[2])) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, ipxcp_pendingnodenumber[3])) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, ipxcp_pendingnodenumber[4])) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						if (!packetServerAddPacketBufferQueue(&pppNakFields, ipxcp_pendingnodenumber[5])) //None!
						{
							goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
						}
						goto ipxcp_requestfixnodenumber; //Request a fix for the node number!
					}
				}

				//Apply the parameters to the session and send back an request-ACK!
				memset(&response, 0, sizeof(response)); //Init the response!
				//Build the PPP header first!
				if (!createPPPsubstream(&pppstream, &pppstream_requestfield, MAX(common_LengthField, 4) - 4)) //Not enough room for the data?
				{
					goto ppp_finishpacketbufferqueue_ipxcp; //Finish up!
				}
				if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, protocol, 0x02, common_IdentifierField, PPP_streamdataleft(&pppstream_requestfield)))
				{
					goto ppp_finishpacketbufferqueue_ipxcp; //Finish up!
				}
				for (; PPP_streamdataleft(&pppstream_requestfield);) //Data left?
				{
					if (!PPP_consumeStream(&pppstream_requestfield, &datab))
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Incorrect packet: discard it!
					}
					if (!packetServerAddPacketBufferQueue(&response, datab)) //Add it!
					{
						goto ppp_finishpacketbufferqueue_ipxcp; //Finish up!
					}
				}
				//Calculate and add the checksum field!
				if (PPP_addFCS(&response))
				{
					goto ppp_finishpacketbufferqueue_ipxcp;
				}
				//Packet is fully built. Now send it!
				if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
				{
					goto ppp_finishpacketbufferqueue_ipxcp; //Keep pending!
				}
				if (response.buffer) //Any response to give?
				{
					memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
					ppp_responseforuser(connectedclient); //A response is ready!
					memset(&response, 0, sizeof(response)); //Parsed!
					//Now, apply the request properly!
					Packetserver_clients[connectedclient].ppp_IPXCPstatus[0] = 1; //Open!
					Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 0; //No negotation anymore!
					memcpy(Packetserver_clients[connectedclient].ipxcp_networknumber[0],&ipxcp_pendingnetworknumber, sizeof(ipxcp_pendingnetworknumber)); //Network number specified or 0 for none!
					memcpy(Packetserver_clients[connectedclient].ipxcp_nodenumber[0],&ipxcp_pendingnodenumber, sizeof(ipxcp_pendingnodenumber)); //Node number or 0 for none!
					Packetserver_clients[connectedclient].ipxcp_routingprotocol[0] = ipxcp_pendingroutingprotocol; //No routing protocol!
				}
			}
			goto ppp_finishpacketbufferqueue2_ipxcp; //Finish up!
			break;
		case 5: //Terminate-Request (Request termination of connection)
			//Send a Code-Reject packet to the client!
			memset(&response, 0, sizeof(response)); //Init the response!
			//Build the PPP header first!
			if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, protocol, 0x06, common_IdentifierField, PPP_streamdataleft(&pppstream)))
			{
				goto ppp_finishpacketbufferqueue_ipxcp;
			}
			//Now, the rejected packet itself!
			for (; PPP_consumeStream(&pppstream, &datab);) //The data field itself follows!
			{
				if (!packetServerAddPacketBufferQueue(&response, datab))
				{
					goto ppp_finishpacketbufferqueue_ipxcp;
				}
			}
			//Calculate and add the checksum field!
			if (PPP_addFCS(&response))
			{
				goto ppp_finishpacketbufferqueue_ipxcp;
			}
			//Packet is fully built. Now send it!
			if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
			{
				goto ppp_finishpacketbufferqueue_ipxcp; //Keep pending!
			}
			if (response.buffer) //Any response to give?
			{
				memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
				ppp_responseforuser(connectedclient); //A response is ready!
				memset(&response, 0, sizeof(response)); //Parsed!
				//Now, apply the request properly!
				Packetserver_clients[connectedclient].ppp_IPXCPstatus[0] = 0; //Closed!
				Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 0; //No negotation yet!
			}
			goto ppp_finishpacketbufferqueue2_ipxcp; //Finish up!
			break;
		case 2: //Configure-Ack (All options OK)
		case 3: //Configure-Nak (Some options unacceptable)
		case 4: //Configure-Reject (Some options not recognisable or acceptable for negotiation)
		case 6: //Terminate-Ack (Acnowledge termination of connection)
		case 7: //Code-Reject (Code field is rejected because it's unknown)
		default: //Unknown Code field?
			//Send a Code-Reject packet to the client!
			memset(&response, 0, sizeof(response)); //Init the response!
			//Build the PPP header first!
			if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, protocol, 0x07, common_IdentifierField, PPP_streamdataleft(&pppstream_informationfield)))
			{
				goto ppp_finishpacketbufferqueue_ipxcp; //Finish up!
			}
			//Now, the rejected packet itself!
			for (; PPP_consumeStream(&pppstream_informationfield, &datab);) //The information field itself follows!
			{
				if (!packetServerAddPacketBufferQueue(&response, datab))
				{
					goto ppp_finishpacketbufferqueue_ipxcp;
				}
			}
			//Calculate and add the checksum field!
			if (PPP_addFCS(&response))
			{
				goto ppp_finishpacketbufferqueue_ipxcp;
			}
			break;
		}
		//Packet is fully built. Now send it!
		if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
		{
			goto ppp_finishpacketbufferqueue_ipxcp; //Keep pending!
		}
		if (response.buffer) //Any response to give?
		{
			memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
			ppp_responseforuser(connectedclient); //A response is ready!
			memset(&response, 0, sizeof(response)); //Parsed!
		}
		goto ppp_finishpacketbufferqueue2_ipxcp; //Success!
	ppp_finishpacketbufferqueue_ipxcp: //An error occurred during the response?
		result = 0; //Keep pending until we can properly handle it!
	ppp_finishpacketbufferqueue2_ipxcp:
		packetServerFreePacketBufferQueue(&response); //Free the queued response!
		packetServerFreePacketBufferQueue(&pppNakFields); //Free the queued response!
		packetServerFreePacketBufferQueue(&pppRejectFields); //Free the queued response!
		break;
	case 0x2B: //IPX datagram?
		if (Packetserver_clients[connectedclient].ppp_IPXCPstatus[0] && Packetserver_clients[connectedclient].ppp_PAPstatus && Packetserver_clients[connectedclient].ppp_LCPstatus[0]) //Fully authenticated and logged in?
		{
			//Handle the IPX packet to be sent!
			if (!createPPPsubstream(&pppstream, &pppstream_requestfield, PPP_streamdataleft(&pppstream))) //Create a substream for the information field?
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			//Now, pppstream_requestfield contains the packet we're trying to send!

			//Now, construct the ethernet header!
			memcpy(&ppptransmitheader.src, &maclocal, 6); //From us!
			ppptransmitheader.dst[0] = 0xFF;
			ppptransmitheader.dst[1] = 0xFF; 
			ppptransmitheader.dst[2] = 0xFF; 
			ppptransmitheader.dst[3] = 0xFF; 
			ppptransmitheader.dst[4] = 0xFF;
			ppptransmitheader.dst[5] = 0xFF; //To a broadcast!
			ppptransmitheader.type = SDL_SwapBE16(0x8137); //We're an IPX packet!

			packetServerFreePacketBufferQueue(&response); //Clear the response to start filling it!

			for (skipdatacounter = 0; skipdatacounter < 14; ++skipdatacounter)
			{
				if (!packetServerAddPacketBufferQueue(&response, 0)) //Start making room for the header!
				{
					goto ppp_finishpacketbufferqueue; //Keep pending!
				}
			}

			memcpy(&response.buffer[0], ppptransmitheader.data, sizeof(ppptransmitheader.data)); //The ethernet header!
			//Now, add the entire packet as the content!
			for (; PPP_peekStream(&pppstream_requestfield,&datab);) //Anything left to add?
			{
				if (!PPP_consumeStream(&pppstream_requestfield, &datab)) //Data failed to read?
				{
					goto ppp_finishpacketbufferqueue; //Finish up!
				}
				if (!packetServerAddPacketBufferQueue(&response, 0)) //Start making room for the header!
				{
					goto ppp_finishpacketbufferqueue; //Keep pending!
				}
			}

			//Now, the packet we've stored has become the packet to send!
			sendpkt_pcap(response.buffer, response.length); //Send the response on the network!
			goto ppp_finishpacketbufferqueue2;
			break;
		}
		//TODO
		//break;
	default: //Unknown protocol?
		ppp_invalidprotocol: //Invalid protocol used when not fully authenticated or verified?
		if (Packetserver_clients[connectedclient].ppp_LCPstatus) //LCP is Open?
		{
			//Send a Code-Reject packet to the client!
			memset(&response, 0, sizeof(response)); //Init the response!
			//Build the PPP header first!
			if (PPP_addLCPNCPResponseHeader(connectedclient, &response, 1, 0xC021, 0x08, Packetserver_clients[connectedclient].ppp_protocolreject_count, PPP_streamdataleft(&pppstream) + 2))
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			if (!packetServerAddPacketBufferQueueBE16(&response, protocol)) //Rejected Protocol!
			{
				goto ppp_finishpacketbufferqueue; //Finish up!
			}
			//Now, the rejected packet itself!
			for (; PPP_consumeStream(&pppstream, &datab);) //The data field itself follows!
			{
				if (!packetServerAddPacketBufferQueue(&response, datab))
				{
					goto ppp_finishpacketbufferqueue;
				}
			}
			//Calculate and add the checksum field!
			if (PPP_addFCS(&response))
			{
				goto ppp_finishpacketbufferqueue;
			}
			//Packet is fully built. Now send it!
			if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
			{
				goto ppp_finishpacketbufferqueue; //Keep pending!
			}
			if (response.buffer) //Any response to give?
			{
				memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
				ppp_responseforuser(connectedclient); //A response is ready!
				memset(&response, 0, sizeof(response)); //Parsed!
				//This doesn't affect any state otherwise!
			}
			goto ppp_finishpacketbufferqueue2; //Finish up!
		}
		break;
	}
	return result; //Currently simply discard it!
}

#include "headers/packed.h"
typedef struct PACKED
{
	word CheckSum;
	word Length;
	byte TransportControl;
	byte PacketType;
	byte DestinationNetworkNumber[4];
	byte DestinationNodeNumber[6];
	word DestinationSocketNumber;
	byte SourceNetworkNumber[4];
	byte SourceNodeNumber[6];
	word SourceSocketNumber;
} IPXPACKETHEADER;
#include "headers/endpacked.h"

//result: 0 to discard the packet. 1 to start sending the packet to the client, 2 to keep it pending in this stage until we're ready to send it to the client.
byte PPP_parseReceivedPacketForClient(sword connectedclient)
{
	ETHERNETHEADER ethernetheader;
	IPXPACKETHEADER ipxheader;
	MODEM_PACKETBUFFER response;
	PPP_Stream pppstream, ipxechostream;
	byte result;
	byte datab;
	result = 0; //Default: discard!
	//Not handled yet. This is supposed to check the packet, parse it and send packets to the connected client in response when it's able to!
	if (Packetserver_clients[connectedclient].ppp_PAPstatus && Packetserver_clients[connectedclient].ppp_LCPstatus) //Fully authenticated and logged in?
	{
		if (Packetserver_clients[connectedclient].pktlen > sizeof(ethernetheader.data)) //Length might be fine?
		{
			result = 1; //Default: pending!

			memcpy(&ethernetheader.data, Packetserver_clients[connectedclient].packet, sizeof(ethernetheader.data)); //Take a look at the ethernet header!
			if (ethernetheader.type != SDL_SwapBE16(0x8137)) //We're not an IPX packet!
			{
				return 0; //Unsupported packet type, discard!
			}

			if (Packetserver_clients[connectedclient].pktlen >= (30 + sizeof(ethernetheader.data))) //Proper IPX packet received?
			{
				memcpy(&ipxheader, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data)], 30); //Get the IPX header from the packet!
				createPPPstream(&ipxechostream, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data)+30], Packetserver_clients[connectedclient].pktlen - (sizeof(ethernetheader.data)+30)); //Create a stream out of the possible echo packet!
				createPPPstream(&pppstream, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data+18)], 12); //Create a stream out of the IPX packet source address!
				if (SDL_SwapBE16(ipxheader.DestinationSocketNumber) == 2) //Echo request?
				{
					if (memcmp(&ipxheader.DestinationNetworkNumber, &Packetserver_clients[connectedclient].ipxcp_networknumber, 4)==0) //Network number match?
					{
						if (memcmp(&ipxheader.DestinationNodeNumber, &ipxbroadcastaddr, 6) == 0) //Destination node is the broadcast address?
						{
							//We're replying to the echo packet!
							if (!Packetserver_clients[connectedclient].ppp_IPXCPstatus[0]) //Not authenticated yet?
							{
								return 0; //Handled, discard!
							}
							//We're authenticated, so send a reply!
							if (sendIPXechoreply(connectedclient, &ipxechostream, &pppstream)) //Sent a reply?
							{
								return 0; //Handled, discard!
							}
							else //Couldn't send a reply packet?
							{
								return 2; //Keep pending until we can send a reply!
							}
						}
						else if (memcmp(&ipxheader.DestinationNodeNumber, &ipxnegotiationnodeaddr, 6) == 0) //Negotiation address is being sent to?
						{
							if (Packetserver_clients[connectedclient].ipxcp_negotiationstatus == 1) //Waiting for negotiation answers?
							{
								if (memcmp(&ipxheader.SourceNodeNumber, &Packetserver_clients[connectedclient].ipxcp_nodenumber[0], 6)) //The requested node number had been found already?
								{
									Packetserver_clients[connectedclient].ipxcp_negotiationstatus = 2; //NAK the connection, as the requested node number had been found in the network!
								}
							}
						}
					}
				}
				//Filter out unwanted IPX network/node numbers that aren't intended for us!
				if (memcmp(&ipxheader.DestinationNetworkNumber, &Packetserver_clients[connectedclient].ipxcp_networknumber[0][0], 4) != 0) //Network number mismatch?
				{
					return 0; //Handled, discard!
				}
				if (memcmp(&ipxheader.DestinationNodeNumber, &Packetserver_clients[connectedclient].ipxcp_nodenumber[0][0], 6) != 0) //Node number mismatch?
				{
					return 0; //Handled, discard!
				}
			}
			else //Wrong length?
			{
				return 0; //Handled, discard!
			}

			//PPP phase of handling the packet has been reached!
			if (!Packetserver_clients[connectedclient].ppp_IPXCPstatus[0]) //Not authenticated yet on the IPX protocol?
			{
				return 0; //Handled, discard!
			}

			if (!Packetserver_clients[connectedclient].ppp_response.buffer) //Already receiving something?
			{
				return 1; //Keep pending until we can receive it!
			}

			//TODO: Determine if the packet is to be received or not deoending on the IPX packet header. Just receive all compatible IPX packets for now.

			memset(&response, 0, sizeof(response)); //Init the response!
			//Build the PPP header first!
			if (PPP_addPPPheader(connectedclient, &response, 1, 0x2B))
			{
				goto ppp_finishpacketbufferqueue_ppprecv;
			}
			createPPPstream(&pppstream, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data)], Packetserver_clients[connectedclient].pktlen - sizeof(ethernetheader.data)); //Create a stream out of the packet!
			//Now, the received packet itself!
			for (; PPP_consumeStream(&pppstream, &datab);) //The information field itself follows!
			{
				if (!packetServerAddPacketBufferQueue(&response, datab))
				{
					goto ppp_finishpacketbufferqueue_ppprecv;
				}
			}
			//Calculate and add the checksum field!
			if (PPP_addFCS(&response))
			{
				goto ppp_finishpacketbufferqueue_ppprecv;
			}
			//Packet is fully built. Now send it!
			if (Packetserver_clients[connectedclient].ppp_response.size) //Previous Response still valid?
			{
				goto ppp_finishpacketbufferqueue_ppprecv; //Keep pending!
			}
			if (response.buffer) //Any response to give?
			{
				memcpy(&Packetserver_clients[connectedclient].ppp_response, &response, sizeof(response)); //Give the response to the client!
				ppp_responseforuser(connectedclient); //A response is ready!
				memset(&response, 0, sizeof(response)); //Parsed!
			}
			result = 0; //Success!
			goto ppp_finishcorrectpacketbufferqueue2_ppprecv; //Success!
		ppp_finishpacketbufferqueue_ppprecv: //An error occurred during the response?
			result = 2; //Keep pending until we can properly handle it!
		ppp_finishcorrectpacketbufferqueue2_ppprecv: //Correctly finished!
			packetServerFreePacketBufferQueue(&response); //Free the queued response!
			return result; //Give the result!
		}
	}
	return 0; //Currently simply discard it!
}



void connectModem(char* number)
{
	if (modem_connect(number))
	{
		modem_responseResult(MODEMRESULT_CONNECT); //Accept!
		modem.offhook = 2; //On-hook(connect)!
		//Not to remain in command mode?
		if (modem.supported<2) //Normal mode?
		{
			modem.datamode = 2; //Enter data mode pending!
		}
		else
		{
			modem.datamode = 1; //Enter data mode!
		}
	}
}

byte modem_connected()
{
	return (modem.connected == 1); //Are we connected or not!
}

byte modem_passthrough()
{
	return (modem.supported >= 2); //In phassthough mode?
}

#include "headers/packed.h"
typedef struct PACKED
{
	//Pseudo IP header
	byte srcaddr[4];
	byte dstaddr[4];
	byte mustbezero;
	byte protocol;
	word UDPlength;
} UDPpseudoheader;
#include "headers/endpacked.h"

#include "headers/packed.h"
typedef struct PACKED
{
	word sourceport;
	word destinationport;
	word length;
	word checksum;
} UDPheader;
#include "headers/endpacked.h"


#include "headers/packed.h"
typedef union PACKED
{
	UDPpseudoheader header;
	byte data[12]; //12 bytes of data!
} UDPpseudoheadercontainer;
#include "headers/endpacked.h"

#include "headers/packed.h"
typedef struct PACKED
{
	byte version_IHL; //Low 4 bits=Version, High 4 bits is size in 32-bit dwords.
	byte DSCP_ECN;
	word totallength;
	word identification;
	byte flags0_2_fragmentoffsethigh7_3; //flags 2:0, fragment offset high 7:3(bits 4:0 of the high byte)
	byte fragmentoffset; //Remainder of fragment offset low byte
	byte TTL;
	byte protocol;
	word headerchecksum;
	byte sourceaddr[4];
	byte destaddr[4];
	//Now come the options, which are optional.
} IPv4header;
#include "headers/endpacked.h"

#include "headers/packed.h"
typedef struct PACKED
{
	word htype;
	word ptype;
	byte hlen;
	byte plen;
	word oper;
	byte SHA[6]; //Sender hardware address
	uint_32 SPA; //Sender protocol address
	byte THA[6]; //Target hardware address
	uint_32 TPA; //Target protocol address
} ARPpackettype;
#include "headers/endpacked.h"

word performUDPchecksum(MODEM_PACKETBUFFER* buffer)
{
	word result;
	uint_32 r;
	uint_32 len;
	word* p;
	r = 0;
	len = buffer->length;
	p = (word*)buffer->buffer; //The data to check!
	for (; len > 1;) //Words left?
	{
		r += *p++; //Read and add!
		len -= 2; //Parsed!
	}
	if (len) //Left?
	{
		r += *((byte*)p); //Read byte left!
	}
	for (; r >> 16;) //Left to wrap?
	{
		r = (r & 0xFFFF) + (r >> 16); //Wrap!
	}
	result = ~r; //One's complement of the result is the result!
	if (result == 0) //0 needs to become FFFF?
	{
		result = 0xFFFF; //Special case!
	}
	return result; //Give the result!
}

//checkreceivechecksum: 0 for calculating the checksum for sending. 1 for performing the checksum (a resulting checksum value of 0 means that the checksum is correct).
word performIPv4checksum(MODEM_PACKETBUFFER* buffer, byte checkreceivechecksum)
{
	uint_32 r;
	uint_32 len;
	uint_32 pos;
	word* p;
	r = 0;
	len = buffer->length;
	p = (word*)buffer->buffer; //The data to check!
	pos = 0; //Init position!
	for (; len > 1;) //Words left?
	{
		if ((pos != 5) || checkreceivechecksum) //Not the checksum field or not including the checksum for sending(for validating it)?
		{
			r += *p++; //Read and add!
		}
		else
		{
			++p; //Add only, ignore the data!
		}
		++pos; //Next position!
		len -= 2; //Parsed!
	}
	//odd amount of bytes shouldn't happen!
	for (; r >> 16;) //Left to wrap?
	{
		r = (r & 0xFFFF) + (r >> 16); //Wrap!
	}
	return ~r; //One's complement of the result is the result!
}

//UDP checksum like IPv4 checksum above, but taking the proper inputs to perform the checksum! When checksum is non-zero, this must match! Otherwise, no checksum is used!
byte doUDP_checksum(byte* ih, byte *udp_header, byte *UDP_data, word UDP_datalength, word *checksum)
{
	word result;
	word dataleft;
	IPv4header curih;
	UDPpseudoheadercontainer uph;
	MODEM_PACKETBUFFER buffer; //For the data to checksum!
	memcpy(&curih, ih, sizeof(curih)); //Make a copy of the header to read!
	memset(&uph, 0x00, sizeof(uph));
	memcpy(&uph.header.srcaddr,&curih.sourceaddr,4); //Source address!
	memcpy(&uph.header.dstaddr,&curih.destaddr,4); //Destination address!
	uph.header.mustbezero = 0x00;
	uph.header.protocol = curih.protocol;
	uph.header.UDPlength = SDL_SwapBE16(8+UDP_datalength); //UDP header + UDP data size

	memset(&buffer, 0, sizeof(buffer)); //Init checksum buffer!
	//Pseudo header first!
	for (dataleft = 0; dataleft < sizeof(uph.data); ++dataleft)
	{
		if (!packetServerAddPacketBufferQueue(&buffer, uph.data[dataleft])) //Add the data to checksum!
		{
			packetServerFreePacketBufferQueue(&buffer); //Clean up!
			return 0; //Failure!
		}
	}
	//Followed by UDP header!
	for (dataleft = 0; dataleft < 8; ++dataleft)
	{
		if ((dataleft & ~1) == 6) //Word at position 6 is the checksum, skip it!
		{
			if (!packetServerAddPacketBufferQueue(&buffer, 0)) //Add the data to checksum, treating it as if it isn't set!
			{
				packetServerFreePacketBufferQueue(&buffer); //Clean up!
				return 0; //Failure!
			}
		}
		else if (!packetServerAddPacketBufferQueue(&buffer, udp_header[dataleft])) //Add the data to checksum!
		{
			packetServerFreePacketBufferQueue(&buffer); //Clean up!
			return 0; //Failure!
		}
	}
	//Followed by UDP data!
	for (dataleft = 0; dataleft < UDP_datalength; ++dataleft)
	{
		if (!packetServerAddPacketBufferQueue(&buffer, UDP_data[dataleft])) //Add the data to checksum!
		{
			packetServerFreePacketBufferQueue(&buffer); //Clean up!
			return 0; //Failure!
		}
	}
	result = performUDPchecksum(&buffer); //Perform the checksum!
	packetServerFreePacketBufferQueue(&buffer); //Clean up!
	*checksum = result; //The checksum!
	return 1; //Success!
}

//UDP checksum like IPv4 checksum above, but taking the proper inputs to perform the checksum!
//checkreceivechecksum: 0 for calculating the checksum for sending. 1 for performing the checksum (a resulting checksum value of 0 means that the checksum is correct).
byte doIPv4_checksum(byte* ih, word headerlength, byte checkreceivechecksum, word *checksum)
{
	word result;
	word dataleft;
	MODEM_PACKETBUFFER buffer; //For the data to checksum!
	memset(&buffer, 0, sizeof(buffer)); //Init!

	for (dataleft = 0; dataleft < headerlength; ++dataleft)
	{
		if (!packetServerAddPacketBufferQueue(&buffer, ih[dataleft])) //Add the data to checksum!
		{
			packetServerFreePacketBufferQueue(&buffer); //Clean up!
			return 0; //Failure!
		}
	}
	result = performIPv4checksum(&buffer, checkreceivechecksum); //Perform the checksum!
	packetServerFreePacketBufferQueue(&buffer); //Clean up!
	*checksum = result; //The checksum!
	return 1; //Success!
}

//Retrieves a 8-byte UDP header from data!
byte getUDPheader(byte* IPv4_header, byte *UDPheader_data, UDPheader* UDP_header, byte dataleft, byte performChecksumForReceive)
{
	word checksum;
	if (dataleft < 8) //Not enough left for a header?
	{
		return 0; //Failed: invalid header!
	}
	memcpy(UDP_header, UDPheader_data, 8); //Set the header directly from the data!
	if ((SDL_SwapBE16(UDP_header->length) + 8) < dataleft) //Not enough room left for the data?
	{
		return 0; //Failed to perform the checksum: this would overflow the buffer!
	}
	if (performChecksumForReceive) //Performing a checksum on it to validate it?
	{
		if (UDP_header->checksum) //Zero is no checksum present!
		{
			if (!doUDP_checksum(IPv4_header, UDPheader_data, UDPheader_data + 8, SDL_SwapBE16(UDP_header->length), &checksum))
			{
				return 0; //Failed to perform the checksum!
			}
			if (checksum != SDL_SwapBE16(UDP_header->checksum)) //Checksum failed?
			{
				return 0; //Failed: Checksum failed!
			}
		}
	}
	return 1; //OK: UDP header and data is OK!
}

//getIPv4header: Retrieves a IPv4 header from a packet and gives it's size. Can also perform checksum check on the input data.
//Retrieves a n-byte IPv4 header from data!
byte getIPv4header(byte* data, IPv4header* IPv4_header, word dataleft, byte performChecksumForReceive, word *result_headerlength)
{
	word checksum;
	word currentheaderlength;
	if (dataleft < 20) //Not enough left for a minimal header?
	{
		return 0; //Failed: invalid header!
	}
	memcpy(IPv4_header, data, 20); //Set the header directly from the data!
	currentheaderlength = ((IPv4_header->version_IHL >> 4) << 2); //Header length, in doublewords!
	if (dataleft < currentheaderlength) //Not enough data for the full header?
	{
		return 0; //Failed: invalid header!
	}
	if (performChecksumForReceive) //Performing a checksum on it to validate it?
	{
		if (!doIPv4_checksum(data, currentheaderlength, 1, &checksum)) //Failed checksum?
		{
			return 0; //Failed: couldn't validate checksum!
		}
		if (checksum) //Checksum failed?
		{
			return 0; //Failed: checksum failed!
		}
	}
	*result_headerlength = currentheaderlength; //The detected header length!
	return 1; //Gotten packet!
}

/*
* setIPv4headerChecksum: Sets and updates the IPv4 header in the packet with checksum.
* data: points to IPv4 header in the packet!
* IPv4_header: the header to set.
*/
byte setIPv4headerChecksum(byte* data, IPv4header* IPv4_header)
{
	word checksum;
	word headerlength;
	headerlength = ((IPv4_header->version_IHL >> 4) << 2); //Header length, in doublewords!
	memcpy(data, IPv4_header, 20); //Update the IP packet as requested!
	if (!doIPv4_checksum(data, headerlength, 0, &checksum)) //Failed checksum creation?
	{
		return 0; //Failed: couldn't validate checksum!
	}
	IPv4_header->headerchecksum = SDL_SwapBE16(checksum); //Set or update the checksum as requested!
	memcpy(data, IPv4_header, 20); //Update the IP header as requested!
	return 1; //Gotten header and updated!
}

/*
* setUDPheaderChecksum: Sets and updates the UDP header in the packet with checksum.
* ipheader: the IP header in the packet
* udp_header_data: the UDP header in the packet
* udpheader: the UDP header to set in the packet
* UDP_data: the start of UDP data in the packet
* UDP_datalength: the length of UDP data in the packet
*/
byte setUDPheaderChecksum(byte* ipheader, byte* udp_header_data, UDPheader *udpheader, byte* UDP_data, word UDP_datalength)
{
	word checksum;
	memcpy(udp_header_data, udpheader, 8); //Set the header directly from the data!
	if (!doUDP_checksum(ipheader,udp_header_data, UDP_data, UDP_datalength, &checksum)) //Failed checksum?
	{
		return 0; //Failed: couldn't validate checksum!
	}
	udpheader->checksum = SDL_SwapBE16(checksum); //Set or update the checksum as requested!
	memcpy(udp_header_data, udpheader, 8); //Update the UDP header as requested!
	return 1; //Gotten header and updated!
}

void updateModem(DOUBLE timepassed) //Sound tick. Executes every instruction.
{
	ARPpackettype ARPpacket, ARPresponse; //ARP packet to send/receive!
	sword connectedclient;
	sword connectionid;
	byte datatotransmit;
	ETHERNETHEADER ethernetheader, ppptransmitheader;
	memset(&ppptransmitheader, 0, sizeof(ppptransmitheader));
	word headertype; //What header type are we?
	uint_32 currentpos;
	modem.timer += timepassed; //Add time to the timer!
	if (modem.escaping) //Escapes buffered and escaping?
	{
		if (modem.timer>=modem.escapecodeguardtime) //Long delay time?
		{
			if (modem.escaping==3) //3 escapes?
			{
				modem.escaping = 0; //Stop escaping!
				modem.datamode = 0; //Return to command mode!
				modem.ATcommandsize = 0; //Start a new command!
				modem_responseResult(MODEMRESULT_OK); //OK message to escape!
			}
			else //Not 3 escapes buffered to be sent?
			{
				for (;modem.escaping;) //Send the escaped data after all!
				{
					--modem.escaping;
					modem_writeCommandData(modem.escapecharacter); //Send the escaped data!
				}
			}
		}
	}

	if (modem.wascommandcompletionechoTimeout) //Timer running?
	{
		modem.wascommandcompletionechoTimeout -= timepassed;
		if (modem.wascommandcompletionechoTimeout <= (DOUBLE)0.0f) //Expired?
		{
			modem.wascommandcompletionecho = 0; //Disable the linefeed echo!
			modem.wascommandcompletionechoTimeout = (DOUBLE)0; //Stop the timeout!
			modem_flushCommandCompletion(); //Execute the command immediately!
		}
	}

	if (modem.detectiontimer[0]) //Timer running?
	{
		modem.detectiontimer[0] -= timepassed;
		if (modem.detectiontimer[0]<=(DOUBLE)0.0f) //Expired?
			modem.detectiontimer[0] = (DOUBLE)0; //Stop timer!
	}
	if (modem.detectiontimer[1]) //Timer running?
	{
		modem.detectiontimer[1] -= timepassed;
		if (modem.detectiontimer[1]<=(DOUBLE)0.0f) //Expired?
			modem.detectiontimer[1] = (DOUBLE)0; //Stop timer!
	}
	if (modem.RTSlineDelay) //Timer running?
	{
		modem.RTSlineDelay -= timepassed;
	}
	if (modem.DTRlineDelay) //Timer running?
	{
		modem.DTRlineDelay -= timepassed;
	}
	if (modem.RTSlineDelay && modem.DTRlineDelay) //Both timing?
	{
		if ((modem.RTSlineDelay<=(DOUBLE)0.0f) && (modem.DTRlineDelay<=(DOUBLE)0.0f)) //Both expired?
		{
			modem.RTSlineDelay = (DOUBLE)0; //Stop timer!
			modem.DTRlineDelay = (DOUBLE)0; //Stop timer!
			modem_updatelines(3); //Update both lines at the same time!
		}
	}
	if (modem.RTSlineDelay) //Timer running?
	{
		if (modem.RTSlineDelay<=(DOUBLE)0.0f) //Expired?
		{
			modem.RTSlineDelay = (DOUBLE)0; //Stop timer!
			modem_updatelines(2); //Update line!
		}
	}
	if (modem.DTRlineDelay) //Timer running?
	{
		if (modem.DTRlineDelay<=(DOUBLE)0.0f) //Expired?
		{
			modem.DTRlineDelay = (DOUBLE)0; //Stop timer!
			modem_updatelines(1); //Update line!
		}
	}

	if ((modem.supported >= 3) && (modem.passthroughlinestatusdirty & 7)) //Dirty lines to handle in passthrough mode?
	{
		if (fifobuffer_freesize(modem.outputbuffer[0]) >= 2) //Enough to send a packet to describe our status change?
		{
			//Send a break(bit 2)/DTR(bit 1)/RTS(bit 0) packet!
			writefifobuffer(modem.outputbuffer[0], 0xFF); //Escape!
			writefifobuffer(modem.outputbuffer[0], ((modem.outputline & 1) << 1) | ((modem.outputline & 2) >> 1) | ((modem.outputline & 0x20)>>3)); //Send DTR, RTS and Break!
			modem.passthroughlinestatusdirty &= ~7; //Acknowledge the new lines!
		}
	}

	modem.serverpolltimer += timepassed;
	if ((modem.serverpolltimer>=modem.serverpolltick) && modem.serverpolltick) //To poll?
	{
		modem.serverpolltimer = fmod(modem.serverpolltimer,modem.serverpolltick); //Polling once every turn!
		if (!(((((modem.linechanges & 1) == 0) && (modem.supported<2)) || ((modem.supported>=2) && ((modem.connected==1) || (modem.ringing)))) && (PacketServer_running == 0))) //Able to accept? Never accept in passthrough mode!
		{
			if ((connectionid = acceptTCPServer()) >= 0) //Are we connected to?
			{
				if (PacketServer_running) //Packet server is running?
				{
					connectedclient = allocPacketserver_client(); //Try to allocate!
					if (connectedclient >= 0) //Allocated?
					{
						Packetserver_clients[connectedclient].connectionid = connectionid; //We're connected like this!
						modem.connected = 2; //Connect as packet server instead, we start answering manually instead of the emulated modem!
						modem.ringing = 0; //Never ring!
						initPacketServer(connectedclient); //Initialize the packet server to be used!
					}
					else //Failed to allocate?
					{
						TCP_DisconnectClientServer(connectionid); //Try and disconnect, if possible!
					}
				}
				else if (connectionid == 0) //Normal behaviour: start ringing!
				{
					modem.connectionid = connectionid; //We're connected like this!
					modem.ringing = 1; //We start ringing!
					modem.registers[1] = 0; //Reset ring counter!
					modem.ringtimer = timepassed; //Automatic time timer, start immediately!
					if ((modem.supported >= 2) && (PacketServer_running == 0)) //Passthrough mode accepted without packet server?
					{
						TCPServer_Unavailable(); //We're unavailable to connect to from now on!
					}
				}
				else //Invalid ID to handle right now(single host only atm)?
				{
					TCP_DisconnectClientServer(connectionid); //Try and disconnect, if possible!
				}
			}
		}
		else //We can't be connected to, stop the server if so!
		{
			TCPServer_Unavailable(); //We're unavailable to connect to!
			if (modem.supported < 2) //Not in passthrough mode? Disconnect any if connected!
			{
				if ((modem.connected == 1) || modem.ringing) //We're connected as a modem?
				{
					TCP_DisconnectClientServer(modem.connectionid);
					modem.connectionid = -1; //Not connected anymore!
					fifobuffer_clear(modem.inputdatabuffer[0]); //Clear the output buffer for the next client!
					fifobuffer_clear(modem.outputbuffer[0]); //Clear the output buffer for the next client!
				}
			}
		}
	}

	if (modem.ringing) //Are we ringing?
	{
		modem.ringtimer -= timepassed; //Time!
		if (modem.ringtimer<=0.0) //Timed out?
		{
			if (modem.ringing & 2) //Ring completed?
			{
				++modem.registers[1]; //Increase numbr of rings!
				if (((modem.registers[0] > 0) && (modem.registers[1] >= modem.registers[0])) || (modem.supported>=2)) //Autoanswer or passthrough mode?
				{
					handleModemAutoAnswer:
					modem.registers[1] = 0; //When connected, clear the register!
					if (modem_connect(NULL)) //Accept incoming call?
					{
						modem_Answered(); //We've answered!
						return; //Abort: not ringing anymore!
					}
				}
				//Wait for the next ring to start!
				modem.ringing &= ~2; //Wait to start a new ring!
				#ifdef IS_LONGDOUBLE
					modem.ringtimer += 3000000000.0L; //3s timer for every ring!
				#else
					modem.ringtimer += 3000000000.0; //3s timer for every ring!
				#endif
			}
			else //Starting a ring?
			{
				if (modem.supported < 2) //Not passthrough mode?
				{
					modem_responseResult(MODEMRESULT_RING); //We're ringing!
					#ifdef IS_LONGDOUBLE
						modem.ringtimer += 3000000000.0L; //3s timer for every ring!
					#else
						modem.ringtimer += 3000000000.0; //3s timer for every ring!
					#endif
				}
				else //Silent autoanswer mode?
				{
					modem.ringing |= 2; //Wait to start a new ring!
					goto handleModemAutoAnswer; //Autoanswer immediately!
				}
				//Wait for the next ring to start!
				modem.ringing |= 2; //Wait to start a new ring!
			}
		}
	}

	modem.networkdatatimer += timepassed;
	if ((modem.networkdatatimer>=modem.networkpolltick) && modem.networkpolltick) //To poll?
	{
		for (;modem.networkdatatimer>=modem.networkpolltick;) //While polling!
		{
			modem.networkdatatimer -= modem.networkpolltick; //Timing this byte by byte!
			if (modem.connected || modem.ringing) //Are we connected?
			{
				if (modem.connected == 2) //Running the packet server?
				{
					for (connectedclient = 0; connectedclient < Packetserver_totalClients; ++connectedclient) //Check all connected clients!
					{
						if (Packetserver_clients[connectedclient].used == 0) continue; //Skip unused clients!
						//Handle packet server packet data transfers into the inputdatabuffer/outputbuffer to the network!
						if (Packetserver_clients[connectedclient].packetserver_receivebuffer) //Properly allocated?
						{
							if (net.packet || Packetserver_clients[connectedclient].packet || ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) || (Packetserver_clients[connectedclient].ppp_response.buffer)) //Packet has been received or processing? Try to start transmit it!
							{
								if (Packetserver_clients[connectedclient].packet == NULL && (net.packet) && (!Packetserver_clients[connectedclient].packet)) //Ready to receive?
								{
									Packetserver_clients[connectedclient].packet = zalloc(net.pktlen,"SERVER_PACKET",NULL); //Allocate a packet to receive!
									if (Packetserver_clients[connectedclient].packet) //Allocated?
									{
										Packetserver_clients[connectedclient].pktlen = net.pktlen; //Save the length of the packet!
										memcpy(Packetserver_clients[connectedclient].packet, net.packet, net.pktlen); //Copy the packet to the active buffer!
									}
									if (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe && (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3)) //Not suitable for consumption by the client yet?
									{
										//This is handled by the protocol itself! It has it's own packet handling code!
									}
									else //Packet ready for sending to the client!
									{
										Packetserver_clients[connectedclient].PPP_packetreadyforsending = 1; //Ready to send to client always!
										Packetserver_clients[connectedclient].PPP_packetpendingforsending = 0; //Not pending for sending by default!
									}
								}
								if (fifobuffer_freesize(Packetserver_clients[connectedclient].packetserver_receivebuffer) >= 2) //Valid to produce more data?
								{
									if ((((Packetserver_clients[connectedclient].packetserver_packetpos == 0) && (Packetserver_clients[connectedclient].packetserver_packetack == 0)) || ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe))) && (Packetserver_clients[connectedclient].packet)) //New packet?
									{
										if (Packetserver_clients[connectedclient].pktlen > (sizeof(ethernetheader.data) + ((Packetserver_clients[connectedclient].packetserver_slipprotocol!=3)?20:(Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe?7:1)))) //Length OK(at least one byte of data and complete IP header) or the PPP packet size (7 extra bytes for PPPOE, 1 byte minimal for PPP)?
										{
											memcpy(&ethernetheader.data, Packetserver_clients[connectedclient].packet, sizeof(ethernetheader.data)); //Copy to the client buffer for inspection!
											//Next, check for supported packet types!
											if (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) //PPP protocol used?
											{
												if (ethernetheader.type == SDL_SwapBE16(0x8863)) //Are we a discovery packet?
												{
													if (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) //Using PPPOE?
													{
														if (PPPOE_handlePADreceived(connectedclient)) //Handle the received PAD packet!
														{
															//Discard the received packet, so nobody else handles it too!
															freez((void**)&net.packet, net.pktlen, "MODEM_PACKET");
															net.packet = NULL; //Discard if failed to deallocate!
															net.pktlen = 0; //Not allocated!
															goto invalidpacket; //Invalid packet!
														}
													}
													//Using PPP, ignore the header type and parse this later!
												}
												headertype = SDL_SwapBE16(0x8864); //Receiving uses normal PPP packets to transfer/receive on the receiver line only!
											}
											else if (Packetserver_clients[connectedclient].packetserver_slipprotocol == 2) //IPX protocol used?
											{
												headertype = SDL_SwapBE16(0x8137); //We're an IPX packet!
											}
											else //IPv4?
											{
												headertype = SDL_SwapBE16(0x0800); //We're an IP packet!
											}
											//Now, check the normal receive parameters!
											if (Packetserver_clients[connectedclient].packetserver_useStaticIP && (headertype == SDL_SwapBE16(0x0800)) && (ethernetheader.type==headertype) && (!((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)))) //IP filter to apply?
											{
												if ((memcmp(&Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 16], Packetserver_clients[connectedclient].packetserver_staticIP, 4) != 0) && (memcmp(&Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 16], packetserver_broadcastIP, 4) != 0)) //Static IP mismatch?
												{
													goto invalidpacket; //Invalid packet!
												}
											}
											if ((memcmp(&ethernetheader.dst, &packetserver_sourceMAC, sizeof(ethernetheader.dst)) != 0) && (memcmp(&ethernetheader.dst, &packetserver_broadcastMAC, sizeof(ethernetheader.dst)) != 0)) //Invalid destination(and not broadcasting)?
											{
												goto invalidpacket; //Invalid packet!
											}
											if (!(((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)))) //Filtering header type?
											{
												if (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) //PPP protocol used?
												{
													if (ethernetheader.type == SDL_SwapBE16(0x8863)) //Are we a discovery packet?
													{
														if (PPPOE_handlePADreceived(connectedclient)) //Handle the received PAD packet!
														{
															//Discard the received packet, so nobody else handles it too!
															freez((void**)&net.packet, net.pktlen, "MODEM_PACKET");
															net.packet = NULL; //Discard if failed to deallocate!
															net.pktlen = 0; //Not allocated!
															goto invalidpacket; //Invalid packet!
														}
													}
													headertype = SDL_SwapBE16(0x8864); //Receiving uses normal PPP packets to transfer/receive on the receiver line only!
												}
												else if (Packetserver_clients[connectedclient].packetserver_slipprotocol == 2) //IPX protocol used?
												{
													headertype = SDL_SwapBE16(0x8137); //We're an IPX packet!
												}
												else //IPv4?
												{
													headertype = SDL_SwapBE16(0x0800); //We're an IP packet!
												}
											}
											if (Packetserver_clients[connectedclient].packetserver_stage != PACKETSTAGE_PACKETS) goto invalidpacket; //Don't handle SLIP/PPP/IPX yet!
											if ((ethernetheader.type != headertype) && (!((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)))) //Invalid type?
											{
												if (ethernetheader.type == SDL_SwapBE16(0x0806)) //ARP?
												{
													if (Packetserver_clients[connectedclient].packetserver_slipprotocol == 1) //IPv4 protocol used?
													{
														//Always handle ARP packets, if we're IPv4 type!
														//TODO: Check if it's a request for us. If so, reply with our IPv4 address!
														memcpy(&ARPpacket,&Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data)],28); //Retrieve the ARP packet!
														if ((SDL_SwapBE16(ARPpacket.htype)==1) && (ARPpacket.ptype==SDL_SwapBE16(0x0800)) && (ARPpacket.hlen==6) && (ARPpacket.plen==4) && (SDL_SwapBE16(ARPpacket.oper)==1))
														{
															//IPv4 ARP request
															//Check it's our IP, send a response if it's us!
															if (Packetserver_clients[connectedclient].packetserver_useStaticIP) //IP filter is used?
															{
																if (memcmp(&ARPpacket.TPA, &packetserver_defaultstaticIP, 4) == 0) //Default Static IP route to server?
																{
																	goto handleserverARP; //Default server packet!
																}
																if (memcmp(&ARPpacket.TPA, &Packetserver_clients[connectedclient].packetserver_staticIP, 4) != 0) //Static IP mismatch?
																{
																	goto invalidpacket; //Invalid packet!
																}
																handleserverARP: //Server ARP or client ARP?
																//It's for us, send a response!
																//Construct the ARP packet!
																ARPresponse.htype = ARPpacket.htype;
																ARPresponse.ptype = ARPpacket.ptype;
																ARPresponse.hlen = ARPpacket.hlen;
																ARPresponse.plen = ARPpacket.plen;
																ARPresponse.oper = SDL_SwapBE16(2); //Reply!
																memcpy(&ARPresponse.THA,&ARPpacket.SHA,6); //To the originator!
																memcpy(&ARPresponse.TPA,&ARPpacket.SPA,4); //Destination IP!
																memcpy(&ARPresponse.SHA,&maclocal,6); //Our MAC address!
																memcpy(&ARPresponse.SPA,&ARPpacket.TPA,4); //Our IP!
																//Construct the ethernet header!
																memcpy(&Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data)],&ARPresponse,28); //Paste the response in the packet we're handling (reuse space)!
																//Now, construct the ethernet header!
																memcpy(&ppptransmitheader,&ethernetheader,sizeof(ethernetheader.data)); //Copy the header!
																memcpy(&ppptransmitheader.src,&maclocal,6); //From us!
																memcpy(&ppptransmitheader.dst,&ARPpacket.SHA,6); //To the requester!
																memcpy(&Packetserver_clients[connectedclient].packet[0],ppptransmitheader.data,sizeof(ppptransmitheader.data)); //The ethernet header!
																//Now, the packet we've stored has become the packet to send back!
																sendpkt_pcap(Packetserver_clients[connectedclient].packet, (28+sizeof(ethernetheader.data))); //Send the response back to the originator!
																
																 //Discard the received packet, so nobody else handles it too!
																freez((void**)&net.packet, net.pktlen, "MODEM_PACKET");
																net.packet = NULL; //Discard if failed to deallocate!
																net.pktlen = 0; //Not allocated!
															}
														}
													}
												}
												if ((!((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)))) //Applying a filter on the type at all? PPP type handles this itself!
												{
													goto invalidpacket; //Invalid packet!
												}
											}
											//Valid packet! Receive it!
											if (Packetserver_clients[connectedclient].packetserver_slipprotocol) //Using slip or PPP protocol?
											{
												if (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) //PPP?
												{
													if (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) //Using PPPOE?
													{
														if (Packetserver_clients[connectedclient].pppoe_discovery_PADS.length == 0) //No PADS received yet? Invalid packet!
														{
															goto invalidpacket; //Invalid packet: not ready yet!
														}
														if (Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 0] != 0x11) //Invalid VER/type?
														{
															goto invalidpacket; //Invalid packet!
														}
														if (Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 1] != 0) //Invalid Type?
														{
															goto invalidpacket; //Invalid packet!
														}
														word length, sessionid, requiredsessionid, pppoe_protocol;
														memcpy(&length, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 4], sizeof(length)); //The length field!
														memcpy(&sessionid, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 2], sizeof(sessionid)); //The length field!
														memcpy(&pppoe_protocol, &Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 6], sizeof(sessionid)); //The length field!
														memcpy(&requiredsessionid, &Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer[sizeof(ethernetheader.data) + 4], sizeof(requiredsessionid)); //The required session id field!
														if (SDL_SwapBE16(length) < 4) //Invalid Length?
														{
															goto invalidpacket; //Invalid packet!
														}
														if (sessionid != requiredsessionid) //Invalid required session id(other client)?
														{
															goto invalidpacket; //Invalid packet!
														}
														if (SDL_SwapBE16(pppoe_protocol) != 0xC021) //Invalid packet type?
														{
															goto invalidpacket; //Invalid packet!
														}
														Packetserver_clients[connectedclient].packetserver_packetpos = sizeof(ethernetheader.data) + 0x8; //Skip the ethernet header and give the raw IP data!
														Packetserver_clients[connectedclient].packetserver_bytesleft = Packetserver_clients[connectedclient].pktlen - Packetserver_clients[connectedclient].packetserver_packetpos; //How much is left to send?
													}
													else //Filter the packet depending on the packet type we're receiving!
													{
														switch (PPP_parseReceivedPacketForClient(connectedclient)) //Failed to receive the packet as proper to use?
														{
														case 0: //Discard it!
															goto invalidpacket; //Invalid packet!
															break;
														case 1: //Received it!
															//Ready/pending is done by the PPP function!
															goto invalidpacket; //Received the packet, so discard it!
															break;
														case 2: //Keep it pending!
															Packetserver_clients[connectedclient].PPP_packetpendingforsending = 1; //Not ready, pending still!
															break;
														}
													}
												}
												else //SLIP?
												{
													Packetserver_clients[connectedclient].packetserver_packetpos = sizeof(ethernetheader.data); //Skip the ethernet header and give the raw IP data!
													Packetserver_clients[connectedclient].packetserver_bytesleft = MIN(Packetserver_clients[connectedclient].pktlen - Packetserver_clients[connectedclient].packetserver_packetpos, SDL_SwapBE16(*((word*)&Packetserver_clients[connectedclient].packet[sizeof(ethernetheader.data) + 2]))); //How much is left to send?
												}
											}
											else //We're using the ethernet header protocol?
											{
												//else, we're using ethernet header protocol, so take the packet and start sending it to the client!
												Packetserver_clients[connectedclient].packetserver_packetack = 1; //We're acnowledging the packet, so start transferring it!
												Packetserver_clients[connectedclient].packetserver_packetpos = 0; //Use the ethernet header as well!
												Packetserver_clients[connectedclient].packetserver_bytesleft = Packetserver_clients[connectedclient].pktlen; //Use the entire packet, unpatched!
											}
										}
										else //Invalid length?
										{
										invalidpacket:
											//Discard the invalid packet!
											freez((void **)&Packetserver_clients[connectedclient].packet, Packetserver_clients[connectedclient].pktlen, "SERVER_PACKET"); //Release the packet to receive new packets again!
											Packetserver_clients[connectedclient].packet = NULL; //No packet!
											if (!((((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3)) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)))) //Not PPP?
											{
												Packetserver_clients[connectedclient].packetserver_packetpos = 0; //Reset packet position for the new packets!
											}
											Packetserver_clients[connectedclient].packetserver_packetack = 0; //Not acnowledged yet!
										}
									}
									if (Packetserver_clients[connectedclient].packetserver_stage != PACKETSTAGE_PACKETS)
									{
										if (Packetserver_clients[connectedclient].packet) //Still have a packet allocated to discard?
										{
											goto invalidpacket; //Discard the received packet!
										}
										goto skipSLIP_PPP; //Don't handle SLIP/PPP because we're not ready yet!
									}
									if ((((Packetserver_clients[connectedclient].packet && (!(((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3)) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)))) || ((((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3)) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) && (Packetserver_clients[connectedclient].ppp_response.size && Packetserver_clients[connectedclient].ppp_response.buffer))))) && ((Packetserver_clients[connectedclient].PPP_packetreadyforsending && (Packetserver_clients[connectedclient].PPP_packetpendingforsending==0)) || ((Packetserver_clients[connectedclient].packetserver_slipprotocol!=3) || (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe && (Packetserver_clients[connectedclient].packetserver_slipprotocol==3))))) //Still a valid packet to send and allowed to send the packet that's stored?
									{
										//Convert the buffer into transmittable bytes using the proper encoding!
										if ((Packetserver_clients[connectedclient].packetserver_bytesleft)) //Not finished yet?
										{
											if ((Packetserver_clients[connectedclient].packetserver_packetpos == 0) && (!Packetserver_clients[connectedclient].PPP_packetstartsent) && (((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3)) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe))) //Packet hasn't been started yet and needs to be started properly?
											{
												writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_END); //END of frame!
												Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND = 1; //Last was END!
												Packetserver_clients[connectedclient].PPP_packetstartsent = 1; //Start has been sent!
												goto doPPPtransmit; //Handle the tranmit of the PPP frame start!
											}
											//Start transmitting data into the buffer, according to the protocol!
											--Packetserver_clients[connectedclient].packetserver_bytesleft;
											if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe == 0)) //PPP?
											{
												datatotransmit = Packetserver_clients[connectedclient].ppp_response.buffer[Packetserver_clients[connectedclient].packetserver_packetpos++]; //Take the PPP packet from the buffer that's responding instead of the raw packet that's received (which is parsed already and in a different format)!
											}
											else //Normal packet that's sent?
											{
												datatotransmit = Packetserver_clients[connectedclient].packet[Packetserver_clients[connectedclient].packetserver_packetpos++]; //Read the data to construct!
											}
											if (Packetserver_clients[connectedclient].packetserver_slipprotocol==3) //PPP?
											{
												if (Packetserver_clients[connectedclient].packetserver_packetpos == ((!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)?0:(sizeof(ethernetheader.data) + 0x8 + 1))) //Starting new packet?
												{
													if (!(Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND) || (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) //Not doubled END and used this way?
													{
														writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_END); //END of frame!
														Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND = 1; //Last was END!
													}
												}

												if (PPPOE_ENCODEDECODE || (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) //Encoding PPP?
												{
													if (datatotransmit == PPP_END) //End byte?
													{
														writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_ESC); //Escaped ...
														writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_ENCODEESC(PPP_END)); //END raw data!
													}
													else if (datatotransmit == PPP_ESC) //ESC byte?
													{
														writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_ESC); //Escaped ...
														writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_ENCODEESC(PPP_ESC)); //ESC raw data!
													}
													else //Normal data?
													{
														if ((!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) && (datatotransmit < 0x20)) //Might need to be escaped?
														{
															if (Packetserver_clients[connectedclient].asynccontrolcharactermap[1] & (1 << (datatotransmit & 0x1F))) //To be escaped?
															{
																writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_ESC); //Escaped ...
																writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_ENCODEESC(PPP_ESC)); //ESC raw data!
															}
															else //Not escaped!
															{
																writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, datatotransmit); //Unescaped!
															}
														}
														else
														{
															writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, datatotransmit); //Unescaped!
														}
													}
													Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND = 0; //Last wasn't END!
												}
												else //Not encoding PPP?
												{
													if (!((Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND) && (datatotransmit == PPP_END))) //Not doubled END?
													{
														writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, datatotransmit); //Raw!
													}
													Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND = (datatotransmit == PPP_END); //Last was END?
												}
											}
											else //SLIP?
											{
												if (datatotransmit == SLIP_END) //End byte?
												{
													writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, SLIP_ESC); //Escaped ...
													writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, SLIP_ESC_END); //END raw data!
												}
												else if (datatotransmit == SLIP_ESC) //ESC byte?
												{
													writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, SLIP_ESC); //Escaped ...
													writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, SLIP_ESC_ESC); //ESC raw data!
												}
												else //Normal data?
												{
													writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, datatotransmit); //Unescaped!
												}
											}
										}
										else //Finished transferring a frame?
										{
											if (Packetserver_clients[connectedclient].packetserver_slipprotocol==3) //PPP?
											{
												if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe == 0)) //PPP?
												{
													writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_END); //END of frame!
													Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND = 0; //Last wasn't END! This is ignored for PPP frames (always send them)!
													packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].ppp_response); //Free the response that's queued for packets to be sent to the client!
													goto doPPPtransmit; //Don't perform normal receive buffer cleanup, as this isn't used here!
												}
												else //PPPOE?
												{
													if (!(Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND)) //Not doubled END?
													{
														writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, PPP_END); //END of frame!
														Packetserver_clients[connectedclient].pppoe_lastrecvbytewasEND = 1; //Last was END!
													}
												}
											}
											else //SLIP?
											{
												writefifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, SLIP_END); //END of frame!
											}
											freez((void **)&Packetserver_clients[connectedclient].packet, Packetserver_clients[connectedclient].pktlen, "SERVER_PACKET"); //Release the packet to receive new packets again!
											Packetserver_clients[connectedclient].packet = NULL; //Discard the packet anyway, no matter what!
											Packetserver_clients[connectedclient].packetserver_packetpos = 0; //Reset packet position!
											Packetserver_clients[connectedclient].packetserver_packetack = 0; //Not acnowledged yet!
										}
									}
								}
							}
							doPPPtransmit: //NOP operation for the PPP packet that's transmitted!
							//Transmit the encoded packet buffer to the client!
							if (fifobuffer_freesize(modem.outputbuffer[connectedclient]) && peekfifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, &datatotransmit)) //Able to transmit something?
							{
								for (; fifobuffer_freesize(modem.outputbuffer[connectedclient]) && peekfifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, &datatotransmit);) //Can we still transmit something more?
								{
									if (writefifobuffer(modem.outputbuffer[connectedclient], datatotransmit)) //Transmitted?
									{
										datatotransmit = readfifobuffer(Packetserver_clients[connectedclient].packetserver_receivebuffer, &datatotransmit); //Discard the data that's being transmitted!
									}
								}
							}
						}

						if (Packetserver_clients[connectedclient].packetserver_stage != PACKETSTAGE_PACKETS)
						{
							goto skipSLIP_PPP; //Don't handle SLIP/PPP because we're not ready yet!
						}

						if (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) //PPP?
						{
							if (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) //Not using PPPOE?
							{
								if (!PPP_parseSentPacketFromClient(connectedclient, 0)) //Parse PPP packets to their respective ethernet or IPv4 protocols for sending to the ethernet layer, as supported!
								{
									goto skipSLIP_PPP; //Keep the packet parsing pending!
								}
							}
						}

						//Handle transmitting packets(with automatically increasing buffer sizing, as a packet can be received of any size theoretically)!
						if (peekfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit)) //Is anything transmitted yet?
						{
							if ((Packetserver_clients[connectedclient].packetserver_transmitlength == 0) && (!((Packetserver_clients[connectedclient].packetserver_slipprotocol==3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)))) //We might need to create an ethernet header?
							{
								//Build an ethernet header, platform dependent!
								//Use the data provided by the settings!
								byte b;
								if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer && Packetserver_clients[connectedclient].pppoe_discovery_PADS.length) //PPP?
								{
									memcpy(&ppptransmitheader.data, &Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer,sizeof(ppptransmitheader.data)); //Make a local copy for usage!
								}
								for (b = 0; b < 6; ++b) //Process MAC addresses!
								{
									if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer && Packetserver_clients[connectedclient].pppoe_discovery_PADS.length) //PPP?
									{
										ethernetheader.dst[b] = ppptransmitheader.src[b]; //The used server MAC is the destination!
										ethernetheader.src[b] = ppptransmitheader.dst[b]; //The Packet server MAC is the source!
									}
									else //SLIP
									{
										ethernetheader.dst[b] = packetserver_gatewayMAC[b]; //Gateway MAC is the destination!
										ethernetheader.src[b] = packetserver_sourceMAC[b]; //Packet server MAC is the source!
									}
								}
								if (Packetserver_clients[connectedclient].packetserver_slipprotocol==3) //PPP?
								{
									if (Packetserver_clients->packetserver_slipprotocol_pppoe) //Using PPPOE?
									{
										if (Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer && Packetserver_clients[connectedclient].pppoe_discovery_PADS.length) //Valid to send?
										{
											ethernetheader.type = SDL_SwapBE16(0x8864); //Our packet type!
										}
										else goto noPPPtransmit; //Ignore the transmitter for now!
									}
									//Otherwise, PPP packet to send? Are we to do something with this now?
								}
								else if (Packetserver_clients[connectedclient].packetserver_slipprotocol==2) //IPX?
								{
									ethernetheader.type = SDL_SwapBE16(0x8137); //We're an IPX packet!
								}
								else //IPv4?
								{
									ethernetheader.type = SDL_SwapBE16(0x0800); //We're an IP packet!
								}
								for (b = 0; b < 14; ++b) //Use the provided ethernet packet header!
								{
									if (!packetServerAddWriteQueue(connectedclient, ethernetheader.data[b])) //Failed to add?
									{
										break; //Stop adding!
									}
								}
								if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) && Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer && Packetserver_clients[connectedclient].pppoe_discovery_PADS.length) //PPP?
								{
									if (!packetServerAddWriteQueue(connectedclient, 0x11)) //V/T?
									{
										goto noPPPtransmit; //Stop adding!
									}
									if (!packetServerAddWriteQueue(connectedclient, 0x00)) //Code?
									{
										goto noPPPtransmit; //Stop adding!
									}
									NETWORKVALSPLITTER.bval[0] = Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer[0x10]; //Session_ID!
									NETWORKVALSPLITTER.bval[1] = Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer[0x11]; //Session_ID!
									if (!packetServerAddWriteQueue(connectedclient, NETWORKVALSPLITTER.bval[0])) //First byte?
									{
										goto noPPPtransmit; //Stop adding!
									}
									if (!packetServerAddWriteQueue(connectedclient, NETWORKVALSPLITTER.bval[1])) //Second byte?
									{
										goto noPPPtransmit; //Stop adding!
									}
									NETWORKVALSPLITTER.wval = SDL_SwapBE16(0); //Length: to be filled in later!
									if (!packetServerAddWriteQueue(connectedclient, NETWORKVALSPLITTER.bval[0])) //First byte?
									{
										goto noPPPtransmit; //Stop adding!
									}
									if (!packetServerAddWriteQueue(connectedclient, NETWORKVALSPLITTER.bval[1])) //Second byte?
									{
										goto noPPPtransmit; //Stop adding!
									}
									NETWORKVALSPLITTER.wval = SDL_SwapBE16(0xC021); //Protocol!
									if (!packetServerAddWriteQueue(connectedclient, NETWORKVALSPLITTER.bval[0])) //First byte?
									{
										goto noPPPtransmit; //Stop adding!
									}
									if (!packetServerAddWriteQueue(connectedclient, NETWORKVALSPLITTER.bval[1])) //Second byte?
									{
										goto noPPPtransmit; //Stop adding!
									}
								}
								if (
									((Packetserver_clients[connectedclient].packetserver_transmitlength != 14) && (Packetserver_clients[connectedclient].packetserver_slipprotocol!=3)) || 
									((Packetserver_clients[connectedclient].packetserver_transmitlength != 22) && (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe))
									) //Failed to generate header?
								{
									dolog("ethernetcard", "Error: Transmit initialization failed. Resetting transmitter!");
									noPPPtransmit:
									if (!(Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer && Packetserver_clients[connectedclient].pppoe_discovery_PADS.length) && Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) //Not ready to send?
									{
										if (!(Packetserver_clients[connectedclient].pppoe_discovery_PADI.buffer && Packetserver_clients[connectedclient].pppoe_discovery_PADI.length)) //No PADI sent yet? Start sending one now to restore the connection!
										{
											PPPOE_requestdiscovery(connectedclient); //Try to request a new discovery for transmitting PPP packets!
										}
										goto skipSLIP_PPP; //Don't handle the sent data yet, prepare for sending by reconnecting to the PPPOE server!
									}
									Packetserver_clients[connectedclient].packetserver_transmitlength = 0; //Abort the packet generation!
								}
							}
							
							//Now, parse the normal packet and decrypt it!
							if (((datatotransmit == SLIP_END) && (Packetserver_clients[connectedclient].packetserver_slipprotocol!=3))
									|| ((datatotransmit==PPP_END) && (Packetserver_clients[connectedclient].packetserver_slipprotocol==3))) //End-of-frame? Send the frame!
							{
								if (Packetserver_clients[connectedclient].packetserver_transmitstate && (Packetserver_clients[connectedclient].packetserver_slipprotocol!=3)) //Were we already escaping?
								{
									if (packetServerAddWriteQueue(connectedclient, SLIP_ESC)) //Ignore the escaped sequence: it's invalid, thus parsed raw!
									{
										Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //We're not escaping something anymore!
									}
								}
								else if (Packetserver_clients[connectedclient].packetserver_transmitstate) //Escaped with  PPP?
								{
									Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //Stopmescaping!
								}
								if (Packetserver_clients[connectedclient].packetserver_transmitstate == 0) //Ready to send the packet(not waiting for the buffer to free)?
								{
									//Clean up the packet container!
									if (
										((Packetserver_clients[connectedclient].packetserver_transmitlength > sizeof(ethernetheader.data)) && (Packetserver_clients[connectedclient].packetserver_slipprotocol!=3)) || //Anything buffered(the header is required)?
										((Packetserver_clients[connectedclient].packetserver_transmitlength > 0x22) && (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) //Anything buffered(the header is required)?
										|| ((Packetserver_clients[connectedclient].packetserver_transmitlength > 0) && (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) //Anything buffered(the header is required)?
										)
									{
										//Send the frame to the server, if we're able to!
										if ((Packetserver_clients[connectedclient].packetserver_transmitlength <= 0xFFFF) || (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3)) //Within length range?
										{
											if (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) //PPP?
											{
												if (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) //Using PPPOE?
												{
													if (!((Packetserver_clients[connectedclient].pppoe_lastsentbytewasEND))) //Not doubled END?
													{
														if (!packetServerAddWriteQueue(connectedclient, PPP_END))
														{
															goto skipSLIP_PPP; //Don't handle the sending of the packet yet: not ready!
														}
														Packetserver_clients[connectedclient].pppoe_lastsentbytewasEND = 1; //Last was END!
													}
												}
											}
											if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) //Length field needs fixing up?
											{
												NETWORKVALSPLITTER.wval = SDL_SwapBE16(Packetserver_clients[connectedclient].packetserver_transmitlength-0x22); //The length of the PPP packet itself!
												Packetserver_clients[connectedclient].packetserver_transmitbuffer[0x12] = NETWORKVALSPLITTER.bval[0]; //First byte!
												Packetserver_clients[connectedclient].packetserver_transmitbuffer[0x13] = NETWORKVALSPLITTER.bval[1]; //Second byte!
											}
											if ((!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) && (Packetserver_clients[connectedclient].packetserver_slipprotocol == 3)) //Able to send the packet for the PPP connection we manage?
											{
												if (!PPP_parseSentPacketFromClient(connectedclient, 1)) //Parse PPP packets to their respective ethernet or IPv4 protocols for sending to the ethernet layer, as supported!
												{
													goto skipSLIP_PPP; //Keep the packet parsing pending!
												}
											}
											else //Able to send the packet always?
											{
												sendpkt_pcap(Packetserver_clients[connectedclient].packetserver_transmitbuffer, Packetserver_clients[connectedclient].packetserver_transmitlength); //Send the packet!
											}
										}
										else
										{
											dolog("ethernetcard", "Error: Can't send packet: packet is too large to send(size: %u)!", Packetserver_clients[connectedclient].packetserver_transmitlength);
										}
										//Now, cleanup the buffered frame!
										freez((void**)&Packetserver_clients[connectedclient].packetserver_transmitbuffer, Packetserver_clients[connectedclient].packetserver_transmitsize, "MODEM_SENDPACKET"); //Free 
										Packetserver_clients[connectedclient].packetserver_transmitsize = 1024; //How large is out transmit buffer!
										Packetserver_clients[connectedclient].packetserver_transmitbuffer = zalloc(1024, "MODEM_SENDPACKET", NULL); //Simple transmit buffer, the size of a packet byte(when encoded) to be able to buffer any packet(since any byte can be doubled)!
									}
									//Silently discard the empty packets!
									Packetserver_clients[connectedclient].packetserver_transmitlength = 0; //We're at the start of this buffer, nothing is sent yet!
									Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //Not escaped anymore!
									readfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit); //Ignore the data, just discard the packet END!
								}
							}
							else if ((Packetserver_clients[connectedclient].packetserver_transmitstate) && (Packetserver_clients[connectedclient].packetserver_slipprotocol==3) && ((!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) || PPPOE_ENCODEDECODE)) //PPP ESCaped value?
							{
								if (Packetserver_clients[connectedclient].packetserver_transmitlength || ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && ((!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)))) //Gotten a valid packet to start adding an escaped value to?
								{
									if (packetServerAddWriteQueue(connectedclient, PPP_DECODEESC(datatotransmit))) //Added to the queue?
									{
										Packetserver_clients[connectedclient].pppoe_lastsentbytewasEND = 0; //Last was not END!
										readfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit); //Ignore the data, just discard the packet byte!
										Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //We're not escaping something anymore!
									}
								}
								else //Unable to parse into the buffer? Discard!
								{
									readfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit); //Ignore the data, just discard the packet byte!
									Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //We're not escaping something anymore!
								}
							}
							else if ((datatotransmit==PPP_ESC) && (Packetserver_clients[connectedclient].packetserver_slipprotocol==3) && ((!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) || PPPOE_ENCODEDECODE)) //PPP ESC?
							{
								readfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit); //Discard, as it's processed!
								Packetserver_clients[connectedclient].packetserver_transmitstate = 1; //We're escaping something! Multiple escapes are ignored and not sent!
							}
							else if ((datatotransmit == SLIP_ESC) && (Packetserver_clients[connectedclient].packetserver_slipprotocol!=3)) //Escaped something?
							{
								if (Packetserver_clients[connectedclient].packetserver_transmitstate) //Were we already escaping?
								{
									if (packetServerAddWriteQueue(connectedclient, SLIP_ESC)) //Ignore the escaped sequence: it's invalid, thus parsed raw!
									{
										Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //We're not escaping something anymore!
									}
								}
								if (Packetserver_clients[connectedclient].packetserver_transmitstate == 0) //Can we start a new escape?
								{
									readfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit); //Discard, as it's processed!
									Packetserver_clients[connectedclient].packetserver_transmitstate = 1; //We're escaping something! Multiple escapes are ignored and not sent!
								}
							}
							else if (Packetserver_clients[connectedclient].packetserver_slipprotocol==3) //Active PPP data?
							{
								if (Packetserver_clients[connectedclient].packetserver_transmitlength || (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) //Gotten a valid packet?
								{
									goto addUnescapedValue; //Process an unescaped PPP value!
								}
							}
							else if (Packetserver_clients[connectedclient].packetserver_slipprotocol!=3) //Active SLIP data?
							{
								if (Packetserver_clients[connectedclient].packetserver_transmitlength) //Gotten a valid packet?
								{
									if (Packetserver_clients[connectedclient].packetserver_transmitstate && (datatotransmit == SLIP_ESC_END)) //Transposed END sent?
									{
										if (packetServerAddWriteQueue(connectedclient,SLIP_END)) //Added to the queue?
										{
											readfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit); //Ignore the data, just discard the packet byte!
											Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //We're not escaping something anymore!
										}
									}
									else if (Packetserver_clients[connectedclient].packetserver_transmitstate && (datatotransmit == SLIP_ESC_ESC)) //Transposed ESC sent?
									{
										if (packetServerAddWriteQueue(connectedclient,SLIP_ESC)) //Added to the queue?
										{
											readfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit); //Ignore the data, just discard the packet byte!
											Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //We're not escaping something anymore!
										}
									}
									else //Parse as a raw data when invalidly escaped or sent unescaped! Also terminate escape sequence as required!
									{
										if (Packetserver_clients[connectedclient].packetserver_transmitstate) //Were we escaping?
										{
											if (packetServerAddWriteQueue(connectedclient, SLIP_ESC)) //Ignore the escaped sequence: it's invalid, thus parsed unescaped!
											{
												Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //We're not escaping something anymore!
											}
										}
										addUnescapedValue:
										if (Packetserver_clients[connectedclient].packetserver_transmitstate==0) //Can we parse the raw data?
										{
											if (packetServerAddWriteQueue(connectedclient, datatotransmit)) //Added to the queue?
											{
												Packetserver_clients[connectedclient].pppoe_lastsentbytewasEND = 0; //Last was not PPP_END!
												readfifobuffer(modem.inputdatabuffer[connectedclient], &datatotransmit); //Ignore the data, just discard the packet byte!
												Packetserver_clients[connectedclient].packetserver_transmitstate = 0; //We're not escaping something anymore!
											}
										}
									}
								}
							}
						}
					skipSLIP_PPP: //SLIP isn't available?

					//Handle an authentication stage
						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_REQUESTUSERNAME)
						{
							authstage_startrequest(timepassed,connectedclient,"username:",PACKETSTAGE_ENTERUSERNAME);
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_ENTERUSERNAME)
						{
							switch (authstage_enterfield(timepassed, connectedclient, &Packetserver_clients[connectedclient].packetserver_username[0], sizeof(Packetserver_clients[connectedclient].packetserver_username),0,(char)0))
							{
							case 0: //Do nothing!
								break;
							case 1: //Finished stage!
								PacketServer_startNextStage(connectedclient, PACKETSTAGE_REQUESTPASSWORD); //Next stage: password!
								break;
							case 2: //Send the output buffer!
								goto sendoutputbuffer;
								break;
							}
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_REQUESTPASSWORD)
						{
							authstage_startrequest(timepassed,connectedclient,"password:",PACKETSTAGE_ENTERPASSWORD);
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_ENTERPASSWORD)
						{
							switch (authstage_enterfield(timepassed, connectedclient, &Packetserver_clients[connectedclient].packetserver_password[0], sizeof(Packetserver_clients[connectedclient].packetserver_password), 0, '*'))
							{
							case 0: //Do nothing!
								break;
							case 1: //Finished stage!
								PacketServer_startNextStage(connectedclient, PACKETSTAGE_REQUESTPROTOCOL); //Next stage: protocol!
								break;
							case 2: //Send the output buffer!
								goto sendoutputbuffer;
								break;
							}
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_REQUESTPROTOCOL)
						{
							authstage_startrequest(timepassed,connectedclient,"protocol:",PACKETSTAGE_ENTERPROTOCOL);
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_ENTERPROTOCOL)
						{
							switch (authstage_enterfield(timepassed, connectedclient, &Packetserver_clients[connectedclient].packetserver_protocol[0], sizeof(Packetserver_clients[connectedclient].packetserver_protocol),1,(char)0))
							{
							case 0: //Do nothing!
								break;
							case 1: //Finished stage!
								if (Packetserver_clients[connectedclient].packetserver_credentials_invalid) goto packetserver_autherror; //Authentication error!
								if (packetserver_authenticate(connectedclient)) //Authenticated?
								{
									Packetserver_clients[connectedclient].packetserver_slipprotocol = ((strcmp(Packetserver_clients[connectedclient].packetserver_protocol, "ppp") == 0) || (strcmp(Packetserver_clients[connectedclient].packetserver_protocol, "pppoe") == 0))?3:((strcmp(Packetserver_clients[connectedclient].packetserver_protocol, "ipxslip") == 0)?2:((strcmp(Packetserver_clients[connectedclient].packetserver_protocol, "slip") == 0) ? 1 : 0)); //Are we using the slip protocol?
									Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe = (strcmp(Packetserver_clients[connectedclient].packetserver_protocol, "pppoe") == 0) ? 1 : 0; //Use PPPOE instead of PPP?
									PacketServer_startNextStage(connectedclient, (Packetserver_clients[connectedclient].packetserver_useStaticIP==2)?PACKETSTAGE_DHCP:PACKETSTAGE_INFORMATION); //We're logged in! Give information stage next!
									if (Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) //Using PPPOE?
									{
										PPPOE_requestdiscovery(connectedclient); //Start the discovery phase of the connected client!
									}
								}
								else goto packetserver_autherror; //Authentication error!
								break;
							case 2: //Send the output buffer!
								goto sendoutputbuffer;
								break;
							}
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_DHCP)
						{
							if (Packetserver_clients[connectedclient].packetserver_useStaticIP == 2) //Sending discovery packet of DHCP?
							{
								//Create and send a discovery packet! Use the packetServerAddPacketBufferQueue to create the packet!
								packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_discoverypacket); //Free the old one first, if present!
								//Now, create the packet to send using a function!
								//Send it!

								Packetserver_clients[connectedclient].packetserver_useStaticIP = 3; //Start waiting for the Offer!
								Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
								Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_DHCP_TIMEOUT; //Delay this until we timeout!
							}

							if (Packetserver_clients[connectedclient].packetserver_useStaticIP == 3) //Waiting for the DHCP Offer?
							{
								Packetserver_clients[connectedclient].packetserver_delay -= timepassed; //Delaying!
								if ((Packetserver_clients[connectedclient].packetserver_delay <= 0.0) || (!Packetserver_clients[connectedclient].packetserver_delay)) //Finished?
								{
									Packetserver_clients[connectedclient].packetserver_delay = (DOUBLE)0; //Finish the delay!
									//Timeout has occurred! Disconnect!
									goto packetserver_autherror; //Disconnect the client: we can't help it!
								}
								if (net.packet) //Packet has been received before the timeout?
								{
									if (0) //Gottten a DHCP packet?
									{
										//Check if it's ours?
										if (0) //It's ours?
										{
											//If an Offer packet, do the following:
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_offerpacket); //Free the old one first, if present!
											//Save it in the storage!
											for (currentpos = 0; currentpos < net.pktlen;) //Parse the entire packet!
											{
												if (!packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_offerpacket, net.packet[currentpos++])) //Failed to save the packet?
												{
													goto packetserver_autherror; //Error out: disconnect!
												}
											}
											Packetserver_clients[connectedclient].packetserver_useStaticIP = 4; //Start sending the Request!
											Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
											Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_DHCP_TIMEOUT; //Delay this until we timeout!
										}
									}
								}
							}
							if (Packetserver_clients[connectedclient].packetserver_useStaticIP == 4) //Sending request packet of DHCP?
							{
								//Create and send a discovery packet! Use the packetServerAddPacketBufferQueue to create the packet!
								packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_requestpacket); //Free the old one first, if present!
								//Now, create the packet to send using a function!
								//Send it!

								Packetserver_clients[connectedclient].packetserver_useStaticIP = 5; //Start waiting for the Acknowledgement!
								Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
								Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_DHCP_TIMEOUT; //Delay this until we timeout!
							}

							if (Packetserver_clients[connectedclient].packetserver_useStaticIP == 5) //Waiting for the DHCP Acknoledgement?
							{
								Packetserver_clients[connectedclient].packetserver_delay -= timepassed; //Delaying!
								if ((Packetserver_clients[connectedclient].packetserver_delay <= 0.0) || (!Packetserver_clients[connectedclient].packetserver_delay)) //Finished?
								{
									Packetserver_clients[connectedclient].packetserver_delay = (DOUBLE)0; //Finish the delay!
									//Timeout has occurred! Disconnect!
									goto packetserver_autherror; //Disconnect the client: we can't help it!
								}
								if (net.packet) //Packet has been received before the timeout?
								{
									if (0) //Gottten a DHCP packet?
									{
										//Check if it's ours?
										if (0) //It's ours?
										{
											//If it's a NACK or Decline, abort!
											if (0) //NACK or Decline?
											{
												goto packetserver_autherror; //Disconnect the client: we can't help it!
											}
											//If an Acknowledgement packet, do the following:
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_offerpacket); //Free the old one first, if present!
											//Save it in the storage!
											for (currentpos = 0; currentpos < net.pktlen;) //Parse the entire packet!
											{
												if (!packetServerAddPacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_offerpacket, net.packet[currentpos++])) //Failed to save the packet?
												{
													goto packetserver_autherror; //Error out: disconnect!
												}
											}
											Packetserver_clients[connectedclient].packetserver_useStaticIP = 6; //Always wait for NACK!
											Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
											Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_DHCP_TIMEOUT; //Delay this until we timeout!
										}
									}
								}
							}

							if (Packetserver_clients[connectedclient].packetserver_useStaticIP == 7) //Sending release packet of DHCP?
							{
								//Create and send a discovery packet! Use the packetServerAddPacketBufferQueue to create the packet!
								packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_releasepacket); //Free the old one first, if present!
								//Now, create the packet to send using a function!
								//Send it!

								Packetserver_clients[connectedclient].packetserver_useStaticIP = 8; //Start waiting for the Acknowledgement!
								Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
								Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_DHCP_TIMEOUT; //Delay this until we timeout!
							}
							if (Packetserver_clients[connectedclient].packetserver_useStaticIP == 8) //Waiting for the DHCP Acknoledgement?
							{
								Packetserver_clients[connectedclient].packetserver_delay -= timepassed; //Delaying!
								if ((Packetserver_clients[connectedclient].packetserver_delay <= 0.0) || (!Packetserver_clients[connectedclient].packetserver_delay)) //Finished?
								{
									Packetserver_clients[connectedclient].packetserver_delay = (DOUBLE)0; //Finish the delay!
									//Timeout has occurred! Disconnect!
									goto packetserver_autherror; //Disconnect the client: we can't help it!
								}
								if (net.packet) //Packet has been received before the timeout?
								{
									if (0) //Gottten a DHCP packet?
									{
										//Check if it's ours?
										if (0) //It's ours?
										{
											//If it's a NACK or Decline, abort!
											if (0) //NACK or Decline?
											{
												goto packetserver_autherror; //Disconnect the client: we can't help it!
											}
											//If an Acknowledgement packet, do the following:
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_discoverypacket); //Free the old one first, if present!
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_offerpacket); //Free the old one first, if present!
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_requestpacket); //Free the old one first, if present!
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_acknowledgepacket); //Free the old one first, if present!
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_releasepacket); //Free the old one first, if present!
											Packetserver_clients[connectedclient].packetserver_useStaticIP = 0; //No request anymore!
											Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
											Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_DHCP_TIMEOUT; //Delay this until we timeout!
										}
									}
								}
							}
						}

						//Check for DHCP release requirement always, even when connected!
						if (Packetserver_clients[connectedclient].packetserver_useStaticIP == 6) //Looking for the DHCP NACK?
						{
							if (net.packet) //Packet has been received before the timeout?
							{
								if (0) //Gottten a DHCP packet?
								{
									//Check if it's ours?
									if (0) //It's ours?
									{
										//If it's a NACK or Decline, abort!
										if (0) //NACK or Decline?
										{
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_discoverypacket); //Free the old one first, if present!
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_offerpacket); //Free the old one first, if present!
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_requestpacket); //Free the old one first, if present!
											packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].DHCP_acknowledgepacket); //Free the old one first, if present!
											goto packetserver_autherror; //Disconnect the client: we can't help it anymore!
										}
									}
								}
							}
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_INFORMATION)
						{
							if (Packetserver_clients[connectedclient].packetserver_stage_byte == PACKETSTAGE_INITIALIZING)
							{
								memset(&Packetserver_clients[connectedclient].packetserver_stage_str, 0, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str));
								snprintf(Packetserver_clients[connectedclient].packetserver_stage_str, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str), "\r\nMACaddress:%02x:%02x:%02x:%02x:%02x:%02x\r\ngatewayMACaddress:%02x:%02x:%02x:%02x:%02x:%02x\r\n", packetserver_sourceMAC[0], packetserver_sourceMAC[1], packetserver_sourceMAC[2], packetserver_sourceMAC[3], packetserver_sourceMAC[4], packetserver_sourceMAC[5], packetserver_gatewayMAC[0], packetserver_gatewayMAC[1], packetserver_gatewayMAC[2], packetserver_gatewayMAC[3], packetserver_gatewayMAC[4], packetserver_gatewayMAC[5]);
								if (Packetserver_clients[connectedclient].packetserver_useStaticIP && (Packetserver_clients[connectedclient].packetserver_slipprotocol!=3)) //IP filter?
								{
									memset(&Packetserver_clients[connectedclient].packetserver_staticIPstr_information, 0, sizeof(Packetserver_clients[connectedclient].packetserver_staticIPstr_information));
									snprintf(Packetserver_clients[connectedclient].packetserver_staticIPstr_information, sizeof(Packetserver_clients[connectedclient].packetserver_staticIPstr_information), "IPaddress:%s\r\n", Packetserver_clients[connectedclient].packetserver_staticIPstr); //Static IP!
									safestrcat(Packetserver_clients[connectedclient].packetserver_stage_str, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str), Packetserver_clients[connectedclient].packetserver_staticIPstr_information); //Inform about the static IP!
								}
								Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
								Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_MESSAGE_DELAY; //Delay this until we start transmitting!
							}
							Packetserver_clients[connectedclient].packetserver_delay -= timepassed; //Delaying!
							if ((Packetserver_clients[connectedclient].packetserver_delay <= 0.0) || (!Packetserver_clients[connectedclient].packetserver_delay)) //Finished?
							{
								Packetserver_clients[connectedclient].packetserver_delay = (DOUBLE)0; //Finish the delay!
								if (writefifobuffer(modem.outputbuffer[connectedclient], Packetserver_clients[connectedclient].packetserver_stage_str[Packetserver_clients[connectedclient].packetserver_stage_byte])) //Transmitted?
								{
									if (++Packetserver_clients[connectedclient].packetserver_stage_byte == safestrlen(Packetserver_clients[connectedclient].packetserver_stage_str, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str))) //Finished?
									{
										PacketServer_startNextStage(connectedclient,PACKETSTAGE_READY); //Start ready stage next!
									}
								}
							}
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_READY)
						{
							if (Packetserver_clients[connectedclient].packetserver_stage_byte == PACKETSTAGE_INITIALIZING)
							{
								memset(&Packetserver_clients[connectedclient].packetserver_stage_str, 0, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str));
								safestrcpy(Packetserver_clients[connectedclient].packetserver_stage_str, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str), "\rCONNECTED\r");
								Packetserver_clients[connectedclient].packetserver_stage_byte = 0; //Init to start of string!
								Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_MESSAGE_DELAY; //Delay this until we start transmitting!
							}
							Packetserver_clients[connectedclient].packetserver_delay -= timepassed; //Delaying!
							if ((Packetserver_clients[connectedclient].packetserver_delay <= 0.0) || (!Packetserver_clients[connectedclient].packetserver_delay)) //Finished?
							{
								if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe) //Requires PAD connection!
								{
									if ((Packetserver_clients[connectedclient].pppoe_discovery_PADS.length && Packetserver_clients[connectedclient].pppoe_discovery_PADS.buffer) == 0) goto sendoutputbuffer; //Don't finish connecting yet! We're requiring an active PADS packet to have been received(PPPOE connection setup)!
								}
								Packetserver_clients[connectedclient].packetserver_delay = (DOUBLE)0; //Finish the delay!
								if (writefifobuffer(modem.outputbuffer[connectedclient], Packetserver_clients[connectedclient].packetserver_stage_str[Packetserver_clients[connectedclient].packetserver_stage_byte])) //Transmitted?
								{
									if (++Packetserver_clients[connectedclient].packetserver_stage_byte == safestrlen(Packetserver_clients[connectedclient].packetserver_stage_str, sizeof(Packetserver_clients[connectedclient].packetserver_stage_str))) //Finished?
									{
										if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) //PPP starts immediately?
										{
											goto startPPPimmediately;
										}
										Packetserver_clients[connectedclient].packetserver_delay = PACKETSERVER_SLIP_DELAY; //Delay this much!
										PacketServer_startNextStage(connectedclient, PACKETSTAGE_SLIPDELAY); //Start delay stage next before starting the server fully!
									}
								}
							}
						}

						if (Packetserver_clients[connectedclient].packetserver_stage == PACKETSTAGE_SLIPDELAY) //Delay before starting SLIP communications?
						{
							Packetserver_clients[connectedclient].packetserver_delay -= timepassed; //Delaying!
							if ((Packetserver_clients[connectedclient].packetserver_delay <= 0.0) || (!Packetserver_clients[connectedclient].packetserver_delay)) //Finished?
							{
								startPPPimmediately: //Start PPP immediately?
								Packetserver_clients[connectedclient].packetserver_delay = (DOUBLE)0; //Finish the delay!
								PacketServer_startNextStage(connectedclient, PACKETSTAGE_PACKETS); //Start the SLIP service!
								if ((Packetserver_clients[connectedclient].packetserver_slipprotocol == 3) && (!Packetserver_clients[connectedclient].packetserver_slipprotocol_pppoe)) //PPP?
								{
									Packetserver_clients[connectedclient].PPP_MRU[0] = Packetserver_clients[connectedclient].PPP_MRU[1] = 1500; //Default: 1500
									Packetserver_clients[connectedclient].PPP_headercompressed[0] = Packetserver_clients[connectedclient].PPP_headercompressed[1] = 0; //Default: uncompressed
									Packetserver_clients[connectedclient].PPP_protocolcompressed[0] = Packetserver_clients[connectedclient].PPP_protocolcompressed[1] = 0; //Default: uncompressed
									Packetserver_clients[connectedclient].ppp_protocolreject_count = 0; //Default: 0!
									Packetserver_clients[connectedclient].ppp_serverLCPstatus = 0; //Start out with initialized PPP LCP connection for the server to client connection!
									initTicksHolder(&Packetserver_clients[connectedclient].ppp_serverLCPrequesttimer); //Initialize the timer!
									getnspassed(&Packetserver_clients[connectedclient].ppp_serverLCPrequesttimer); //Starting it's timing!
									Packetserver_clients[connectedclient].ppp_LCPstatus[0] = Packetserver_clients[connectedclient].ppp_PAPstatus[0] = Packetserver_clients[connectedclient].ppp_IPXCPstatus[0] = 0; //Reset all protocols to init state!
									Packetserver_clients[connectedclient].asynccontrolcharactermap[0] = Packetserver_clients[connectedclient].asynccontrolcharactermap[1] = 0xFFFFFFFF; //Initialize the Async Control Character Map to init value!
									packetServerFreePacketBufferQueue(&Packetserver_clients[connectedclient].ppp_response); //Free the response that's queued for packets to be sent to the client if anything is left!
								}
							}
						}
					}
				}

			sendoutputbuffer:
				if ((modem.connected == 1) && (modem.connectionid>=0)) //Normal connection?
				{
					if (peekfifobuffer(modem.outputbuffer[0], &datatotransmit)) //Byte available to send?
					{
						switch (TCP_SendData(modem.connectionid, datatotransmit)) //Send the data?
						{
						case 0: //Failed to send?
							break; //Simply keep retrying until we can send it!
							modem.connected = 0; //Not connected anymore!
							if (PacketServer_running == 0) //Not running a packet server?
							{
								TCP_DisconnectClientServer(modem.connectionid); //Disconnect!
								modem.connectionid = -1;
								fifobuffer_clear(modem.inputdatabuffer[0]); //Clear the output buffer for the next client!
								fifobuffer_clear(modem.outputbuffer[0]); //Clear the output buffer for the next client!
								modem.connected = 0; //Not connected anymore!
								if (modem.supported < 2) //Normal mode?
								{
									modem_responseResult(MODEMRESULT_NOCARRIER);
								}
								modem.datamode = 0; //Drop out of data mode!
								modem.ringing = 0; //Not ringing anymore!
							}
							else //Disconnect from packet server?
							{
								terminatePacketServer(modem.connectionid); //Clean up the packet server!
								fifobuffer_clear(modem.inputdatabuffer[0]); //Clear the output buffer for the next client!
								fifobuffer_clear(modem.outputbuffer[0]); //Clear the output buffer for the next client!
							}
							break; //Abort!
						case 1: //Sent?
							readfifobuffer(modem.outputbuffer[0], &datatotransmit); //We're send!
							break;
						default: //Unknown function?
							break;
						}
					}
					if (fifobuffer_freesize(modem.inputdatabuffer[0])) //Free to receive?
					{
						if (likely(modem.breakPending == 0)) //Not a pending break? If pending, don't receive new data until processed!
						{
							switch (TCP_ReceiveData(modem.connectionid, &datatotransmit))
							{
							case 0: //Nothing received?
								break;
							case 1: //Something received?
								if (modem.supported >= 3) //Passthrough mode with data lines that can be escaped?
								{
									if (modem.passthroughescaped) //Was the last byte an escape?
									{
										if (datatotransmit == 0xFF) //Escaped non-escaped byte?
										{
											if ((modem.passthroughlines & 4) == 0) //Not in break state?
											{
												writefifobuffer(modem.inputdatabuffer[0], datatotransmit); //Add the transmitted data to the input buffer!
											}
										}
										else //DTR/RTS/break received?
										{
											if (unlikely(((modem.passthroughlines & (modem.passthroughlines ^ datatotransmit)) & 4))) //Break was raised?
											{
												modem.breakPending = 0x10; //Pending break has been received!
											}
											modem.passthroughlines = datatotransmit; //The received lines!
										}
										modem.passthroughescaped = 0; //Not escaped anymore!
									}
									else if (datatotransmit == 0xFF) //New command! Escaped?
									{
										modem.passthroughescaped = 1; //Escaped now!
									}
									else //Non-escaped data!
									{
										if ((modem.passthroughlines & 4) == 0) //Not in break state?
										{
											writefifobuffer(modem.inputdatabuffer[0], datatotransmit); //Add the transmitted data to the input buffer!
										}
									}
								}
								else //Normal mode?
								{
									writefifobuffer(modem.inputdatabuffer[0], datatotransmit); //Add the transmitted data to the input buffer!
								}
								break;
							case -1: //Disconnected?
								modem.connected = 0; //Not connected anymore!
								if (PacketServer_running == 0) //Not running a packet server?
								{
									TCP_DisconnectClientServer(modem.connectionid); //Disconnect!
									modem.connectionid = -1;
									fifobuffer_clear(modem.inputdatabuffer[0]); //Clear the output buffer for the next client!
									fifobuffer_clear(modem.outputbuffer[0]); //Clear the output buffer for the next client!
									modem.connected = 0; //Not connected anymore!
									if (modem.supported < 2) //Not in passthrough mode?
									{
										modem_responseResult(MODEMRESULT_NOCARRIER);
									}
									modem.datamode = 0; //Drop out of data mode!
									modem.ringing = 0; //Not ringing anymore!
								}
								else //Disconnect from packet server?
								{
									terminatePacketServer(modem.connectionid); //Clean up the packet server!
									fifobuffer_clear(modem.inputdatabuffer[0]); //Clear the output buffer for the next client!
									fifobuffer_clear(modem.outputbuffer[0]); //Clear the output buffer for the next client!
								}
								break;
							default: //Unknown function?
								break;
							}
						}
					}
				}
				//Next, process the connected clients!
				else if (modem.connected == 2) //SLIP server connection is active?
				{
					for (connectedclient = 0; connectedclient < Packetserver_totalClients; ++connectedclient) //Check all connected clients!
					{
						if (Packetserver_clients[connectedclient].used == 0) continue; //Skip unused clients!
						if (peekfifobuffer(modem.outputbuffer[connectedclient], &datatotransmit)) //Byte available to send?
						{
							switch (TCP_SendData(Packetserver_clients[connectedclient].connectionid, datatotransmit)) //Send the data?
							{
							case 0: //Failed to send?
								break; //Simply keep retrying until we can send it!
							packetserver_autherror: //Packet server authentication error?
								if (PacketServer_running == 0) //Not running a packet server?
								{
									PPPOE_finishdiscovery(connectedclient); //Finish discovery, if needed!
									TCP_DisconnectClientServer(modem.connectionid); //Disconnect!
									modem.connectionid = -1;
									fifobuffer_clear(modem.inputdatabuffer[connectedclient]); //Clear the output buffer for the next client!
									fifobuffer_clear(modem.outputbuffer[connectedclient]); //Clear the output buffer for the next client!
									modem.connected = 0; //Not connected anymore!
									modem_responseResult(MODEMRESULT_NOCARRIER);
									modem.datamode = 0; //Drop out of data mode!
									modem.ringing = 0; //Not ringing anymore!
								}
								else //Disconnect from packet server?
								{
									PPPOE_finishdiscovery(connectedclient); //Finish discovery, if needed!
									TCP_DisconnectClientServer(Packetserver_clients[connectedclient].connectionid); //Clean up the packet server!
									Packetserver_clients[connectedclient].connectionid = -1; //Not connected!
									terminatePacketServer(connectedclient); //Stop the packet server, if used!
									if (Packetserver_clients[connectedclient].DHCP_acknowledgepacket.length) //We're still having a lease?
									{
										PacketServer_startNextStage(connectedclient, PACKETSTAGE_DHCP);
										Packetserver_clients[connectedclient].packetserver_useStaticIP = 7; //Start the release of the lease!
										Packetserver_clients[connectedclient].used = 2; //Special use case: we're in the DHCP release-only state!
									}
									else //Normal release?
									{
										normalFreeDHCP(connectedclient);
										freePacketserver_client(connectedclient); //Free the client list item!
									}
									fifobuffer_clear(modem.inputdatabuffer[connectedclient]); //Clear the output buffer for the next client!
									fifobuffer_clear(modem.outputbuffer[connectedclient]); //Clear the output buffer for the next client!
									if (Packetserver_availableClients == Packetserver_totalClients) //All cleared?
									{
										modem.connected = 0; //Not connected anymore!
									}
								}
								break; //Abort!
							case 1: //Sent?
								readfifobuffer(modem.outputbuffer[connectedclient], &datatotransmit); //We're send!
								break;
							default: //Unknown function?
								break;
							}
						}
						if (fifobuffer_freesize(modem.inputdatabuffer[connectedclient])) //Free to receive?
						{
							switch (TCP_ReceiveData(Packetserver_clients[connectedclient].connectionid, &datatotransmit))
							{
							case 0: //Nothing received?
								break;
							case 1: //Something received?
								writefifobuffer(modem.inputdatabuffer[connectedclient], datatotransmit); //Add the transmitted data to the input buffer!
								break;
							case -1: //Disconnected?
								if (PacketServer_running == 0) //Not running a packet server?
								{
									TCP_DisconnectClientServer(modem.connectionid); //Disconnect!
									modem.connectionid = -1;
									fifobuffer_clear(modem.inputdatabuffer[connectedclient]); //Clear the output buffer for the next client!
									fifobuffer_clear(modem.outputbuffer[connectedclient]); //Clear the output buffer for the next client!
									modem.connected = 0; //Not connected anymore!
									modem_responseResult(MODEMRESULT_NOCARRIER);
									modem.datamode = 0; //Drop out of data mode!
									modem.ringing = 0; //Not ringing anymore!
								}
								else //Disconnect from packet server?
								{
									if (Packetserver_clients[connectedclient].used) //Still an used client? Prevent us from working on a disconnected client!
									{
										PPPOE_finishdiscovery(connectedclient); //Finish discovery, if needed!
										terminatePacketServer(connectedclient); //Clean up the packet server!
										if (Packetserver_clients[connectedclient].DHCP_acknowledgepacket.length) //We're still having a lease?
										{
											PacketServer_startNextStage(connectedclient, PACKETSTAGE_DHCP);
											Packetserver_clients[connectedclient].packetserver_useStaticIP = 7; //Start the release of the lease!
											Packetserver_clients[connectedclient].used = 2; //Special use case: we're in the DHCP release-only state!
										}
										else //Normal release?
										{
											normalFreeDHCP(connectedclient);
											freePacketserver_client(connectedclient); //Free the client list item!
										}
										fifobuffer_clear(modem.inputdatabuffer[connectedclient]); //Clear the output buffer for the next client!
										fifobuffer_clear(modem.outputbuffer[connectedclient]); //Clear the output buffer for the next client!
										if (Packetserver_availableClients == Packetserver_totalClients) //All cleared?
										{
											modem.connected = 0; //Not connected anymore!
										}
									}
								}
								break;
							default: //Unknown function?
								break;
							}
						}
					}
				}
			} //Connected?

			if (net.packet) //Packet received? Discard anything we receive now for other users!
			{
				freez((void **)&net.packet, net.pktlen, "MODEM_PACKET");
				net.packet = NULL; //Discard if failed to deallocate!
				net.pktlen = 0; //Not allocated!
			}

			fetchpackets_pcap(); //Handle any packets that need fetching!
		} //While polling?
	} //To poll?
}
