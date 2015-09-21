

#ifndef _TLS_Q_INC_
#define _TLS_Q_INC_

#pragma comment(lib, "tls_l.lib")
#pragma comment(linker, "/include:___TlsInfor")

//不要随便改动顺序
#define SPECIFY_TLS_CALLBACK(tls_callback) \
struct { \
	DWORD flag;	\
	PIMAGE_TLS_CALLBACK 	TlsCallback;	\
} _x_ = {'FlAg', (PIMAGE_TLS_CALLBACK)tls_callback, };
	
#define USE_TLS_CALLBACK() _x_.flag = 0; 


#endif /* _TLS_Q_INC_ */
	