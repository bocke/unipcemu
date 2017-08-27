#include "headers/types.h" //Basic type support!
#include "headers/support/log.h" //Logging support!
#include "headers/support/tcphelper.h" //TCP module support!

#define NET_LOGFILE "net"

#if defined(SDL_NET) || defined(SDL2_NET)
#if defined(SDL2) && defined(SDL2_NET)
#define GOTNET
#include "SDL_net.h" //SDL2 NET support!
#else
#ifdef SDL_NET
#define GOTNET
#include "SDL_net.h"
#endif
#endif
#endif

//Some server port to use when listening and sending data packets.
#ifdef GOTNET
TCPsocket server_socket;
TCPsocket mysock;
SDLNet_SocketSet listensocketset;
word SERVER_PORT = 23; //What server port to apply?
byte TCP_BlockIncoming = 0; //Block incoming connections while connected?
#endif

byte NET_READY = 0; //Are we ready to be used?
byte Server_READY = 0; //Server ready for use?
byte Client_READY = 0; //Client ready for use?

void initTCP() //Initialize us!
{
#ifdef GOTNET
	atexit(&doneTCP); //Automatically terminate us when used!
	if(SDL_Init(SDL_INIT_TIMER|SDL_INIT_EVENTS) != 0) {
		dolog(NET_LOGFILE, "ER: SDL_Init: %s\n", SDL_GetError());
		NET_READY  = 0; //Not ready!
		return;
	}
 
	if(SDLNet_Init() == -1) {
		dolog(NET_LOGFILE, "ER: SDLNet_Init: %s\n", SDLNet_GetError());
		NET_READY = 0; //Not ready!
		return;
	}
	NET_READY = 1; //NET is ready!
#endif
	//Initialize buffers for the server, as well as for the client, if used!
	/*
	byte client;
	for (client=0;client<;)
	*/
}

byte TCP_ConnectServer(word port)
{
#ifdef GOTNET
	if (Server_READY==1) return 1; //Already started!
	Server_READY = 0; //Not ready by default!
	if (!NET_READY)
	{
		return 0; //Fail automatically!
	}
	IPaddress ip;
	SERVER_PORT = port;
	if(SDLNet_ResolveHost(&ip, NULL, SERVER_PORT) == -1) {
		//fprintf(stderr, "ER: SDLNet_ResolveHost: %s\n", SDLNet_GetError());
		return 0; //Failed!
	}
 
	server_socket = SDLNet_TCP_Open(&ip);
	if(server_socket == NULL) {
		//fprintf(stderr, "ER: SDLNet_TCP_Open: %s\n", SDLNet_GetError());
		return 0; //Failed!
	}

	Server_READY = 1; //First step successful!

	//Clear the server I/O buffers!
	return 1; //Connected!
#else
return 0; //Cannot connect!
#endif
}
#ifdef GOTNET
byte TCP_connectClientFromServer(TCPsocket source)
{
	//Accept a client as a new server?
	if (Client_READY) return 0; //Already connected?
	Client_READY = 0;
	
	mysock=0;
	listensocketset=0;
	if(source!=0) {
		mysock = source;
		listensocketset = SDLNet_AllocSocketSet(1);
		if(!listensocketset) return 0;
		SDLNet_TCP_AddSocket(listensocketset, source);

		Client_READY=2; //Connected as a server!
		return 1; //Connected!
	}
	return 0; //Accepting calls aren't supported yet!
}
#endif

byte acceptTCPServer() //Update anything needed on the TCP server!
{
#ifdef GOTNET
	if (NET_READY==0) return 0; //Not ready!
	if (Server_READY==0) return 0; //Not ready!
	if (Client_READY || TCP_BlockIncoming) return 0; //Don't allow incoming connections if we're already connected!
	TCPsocket new_tcpsock;
	new_tcpsock=SDLNet_TCP_Accept(server_socket);
	if(!new_tcpsock) {
		//printf("SDLNet_TCP_Accept: %s\n", SDLNet_GetError());
		return 0;
	}
	return TCP_connectClientFromServer(new_tcpsock); //Accept as a client!
#endif
	return 0; //Not supported!
}

void stopTCPServer()
{
#ifdef GOTNET
	if (!NET_READY) return; //Abort when not running properly!
	if (Server_READY>=1) //Loaded the server?
	{
		SDLNet_TCP_Close(server_socket);
		server_socket = NULL; //Nothing anymore!
		--Server_READY; //Layer destroyed!
	}
	Server_READY = 0; //Not ready anymore! 
#endif
}

byte TCP_ConnectClient(const char *destination, word port)
{
#ifdef GOTNET
	IPaddress openip;
	byte TCP_Serving;
	if (Client_READY) return 0; //Can't connect: already connected!
	TCP_BlockIncoming |= 2; //Block incoming connections now!
	TCP_Serving = Server_READY; //Were we serving?
	if (TCP_Serving) //Is the server running? We need to stop it to prevent connecting to ourselves!
	{
		TCP_DisconnectClientServer(); //Disconnect!
		stopTCPServer(); //Stop the server!
	}
	//Ancient versions of SDL_net had this as char*. People still appear to be using this one.
	if (!SDLNet_ResolveHost(&openip,destination,port)) {
		listensocketset = SDLNet_AllocSocketSet(1);
		if(!listensocketset) { TCP_BlockIncoming &= ~2; return 0; }
		mysock = SDLNet_TCP_Open(&openip);
		if(!mysock) { TCP_BlockIncoming &= ~2; return 0; }
		if (SDLNet_TCP_AddSocket(listensocketset, mysock)!=-1)
		{
			Client_READY=1; //Connected as a client!
			TCP_BlockIncoming &= ~2; //Don't block incoming connections anymore!
			return 1; //Successfully connected!
		}
	}
	TCP_BlockIncoming &= ~2; //Don't block incoming connections anymore!
	if (TCP_Serving) //Were we serving?
	{
		TCP_ConnectServer(SERVER_PORT); //Reconnect the TCP server!
	}
	return 0; //Failed to connect!
#endif
	return 0; //Not supported!
}

byte TCP_SendData(byte data)
{
#ifdef GOTNET
	if (!Client_READY) return 0; //Not connected?
	if(SDLNet_TCP_Send(mysock, &data, 1)!=1) {
		Client_READY=0; //Not connected anymore!
		return 0;
	}
	return 1;
#endif
	return 0; //Not supported!
}

sbyte TCP_ReceiveData(byte *result)
{
#ifdef GOTNET
	if (!Client_READY) return -1; //Not connected?
	if(SDLNet_CheckSockets(listensocketset,0))
	{
		byte retval=0;
		if(SDLNet_TCP_Recv(mysock, &retval, 1)!=1) {
			Client_READY=0;
			return -1; //Socket closed
		} else
		{
			*result = retval; //Data read!
			return 1; //Got data!
		}
	}
	else return 0; //No data to receive!
#endif
	return -1; //No socket by default!
}

byte TCP_DisconnectClientServer()
{
#ifdef GOTNET
	if (!Client_READY) return 0; //Can't disconnect!
	if(mysock) {
		if(listensocketset) SDLNet_TCP_DelSocket(listensocketset,mysock);
		SDLNet_TCP_Close(mysock);
	}

	if(listensocketset) SDLNet_FreeSocketSet(listensocketset);
	Client_READY = 0; //Client has become not ready!
	return 1; //Disconnected!
#endif
	return 0; //Error: not connected!
}

void TCPServer_pause()
{
#ifdef GOTNET
	TCP_BlockIncoming |= 1; //Block incoming connections!
#endif
}

void TCPServer_restart()
{
#ifdef GOTNET
	if (TCP_BlockIncoming&1) //Paused before?
	{
		TCP_BlockIncoming &= ~1; //Not blocked anymore!
		return; //Just unblock, nothing more!
	}

	//Not blocked? Actually restart the entire server from scratch while connected.
	TCP_DisconnectClientServer(); //Disconnect if connected: don't accept!
	stopTCPServer(); //Stop the TCP server!
	TCP_ConnectServer(SERVER_PORT); //Reconnect to the TCP server!
#endif
}

void doneTCP(void) //Finish us!
{
#ifdef GOTNET
	if (NET_READY) //Loaded?
	{
		SDLNet_Quit();
		NET_READY = 0; //Not ready anymore!
	}
#endif
}