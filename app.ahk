#noenv
#persistent
#singleinstance force
#notrayicon
#Include %A_ScriptDir%\modules
#include httprequest.ahk\export.ahk
#include oauth.ahk\export.ahk

#Include %A_ScriptDir%\node_modules
#Include biga.ahk\export.ahk
#Include json.ahk\export.ahk

setworkingdir % a_scriptdir

MAIN()
return

rctrl::reload
return

Esc::
ExitApp, 1
return


; ---------------------variables---------------------
A := new biga()

; ---------------------config---------------------

; example requests
; GET https://api.cardmarket.com/ws/v1.1/articles/user/JonDoe


; ---------------------tools---------------------
;http://lti.tools/oauth/


MAIN()
{	global
	useStaticCredentials := false
	if (useStaticCredentials) {	
		credentials := {}
		credentials.auth_consumer_key := "bfaD9xOU0SXBhtBP"
		credentials.oauth_consumer_secret := "pChvrpp6AEOEwxBIIUBOvWcRG3X9xL4Y"
		credentials.oauth_token := "lBY1xptUJ7ZJSK01x4fNwzw8kAe5b10Q"
		credentials.oauth_token_secret := "hc1wJAOX02pGGJK2uAv1ZOiwS7I9Tpoe"
	} else {
		; read credentials from disk
		FileRead, OutputVar, %A_ScriptDir%\credentials.json
		credentials := JSON.parse(OutputVar)
	}
	realm := "https://api.cardmarket.com/ws/v1.1/output.json/games"
	

	responseObj := M4(credentials, "https://api.cardmarket.com/ws/v1.1/output.json/games")
	msgbox, % A.printObj(responseObj)
}

M4(param_credentials, param_request) {    
	global

	; create the credentials_string
    credentials_string := ""
    . "oauth_consumer_key=" param_credentials.auth_consumer_key 
    . "`noauth_consumer_secret=" param_credentials.oauth_consumer_secret 
    . "`nrealm=" param_request
    . "`noauth_token=" param_credentials.oauth_token
    . "`noauth_token_secret=" param_credentials.oauth_token_secret

	; create header
    header := OAuth_Authorization(credentials_string, param_request)

	; create HTTP Req
    WinHTTP := comobjcreate("WinHttp.WinHttpRequest.5.1")
    WinHTTP.Open("GET", param_request, false)
    WinHTTP.SetRequestHeader("Accept", "application/json")
    WinHTTP.SetRequestHeader("Authorization", header)

	; Send and recieve response
    WinHTTP.Send()
    WinHTTP.waitforresponse()
    
	; return response if not blank
    if (A.startsWith(WinHTTP.ResponseText, "2") { ; if server responded with 2XX
		return JSON.parse(WinHTTP.ResponseText)
	} else {
		return false
	}
}

;######### FUNCTIONS #####################################################################################################
bcrypt_sha1_hmac(string,hmac,encoding:="utf-8")
{   static BCRYPT_SHA1_ALGORITHM       := "SHA1"
    static BCRYPT_ALG_HANDLE_HMAC_FLAG := 0x00000008
    static BCRYPT_OBJECT_LENGTH        := "ObjectLength"
    static BCRYPT_HASH_LENGTH          := "HashDigestLength"
	try 
	{	;loads the specified module into the address space of the calling process
		if !(hBCRYPT:=DllCall("LoadLibrary","str","bcrypt.dll","ptr"))
			throw Exception("Failed to load bcrypt.dll",-1)
		;open an algorithm handle
		if (NT_STATUS:=DllCall("bcrypt\BCryptOpenAlgorithmProvider","ptr*",hAlg,"ptr",&BCRYPT_SHA1_ALGORITHM,"ptr",0,"uint",BCRYPT_ALG_HANDLE_HMAC_FLAG)!=0)
			throw Exception("BCryptOpenAlgorithmProvider: " NT_STATUS,-1)
		;calculate the size of the buffer to hold the hash object
		if (NT_STATUS:=DllCall("bcrypt\BCryptGetProperty","ptr",hAlg,"ptr",&BCRYPT_OBJECT_LENGTH,"uint*",cbHashObject,"uint",4,"uint*",cbData,"uint",0)!=0)
			throw Exception("BCryptGetProperty: " NT_STATUS,-1)
		;allocate the hash object
		VarSetCapacity(pbHashObject,cbHashObject,0) ;throw Exception("Memory allocation failed",-1)
		;calculate the length of the hash
		if (NT_STATUS:=DllCall("bcrypt\BCryptGetProperty","ptr",hAlg,"ptr",&BCRYPT_HASH_LENGTH,"uint*",cbHash,"uint",4,"uint*",cbData,"uint",0)!=0)
			throw Exception("BCryptGetProperty: " NT_STATUS,-1)
		;allocate the hash buffer
		VarSetCapacity(pbHash,cbHash,0) ;throw Exception("Memory allocation failed",-1)
		;create a hash
		VarSetCapacity(pbSecret,(StrPut(hmac,encoding)-1)*((encoding="utf-16"||encoding="cp1200")?2:1),0)&&cbSecret:=StrPut(hmac,&pbSecret,encoding)-1
		if (NT_STATUS:=DllCall("bcrypt\BCryptCreateHash","ptr",hAlg,"ptr*",hHash,"ptr",&pbHashObject,"uint",cbHashObject,"ptr",&pbSecret,"uint",cbSecret,"uint", 0) != 0)
			throw Exception("BCryptCreateHash: " NT_STATUS,-1)
		;hash some data
		VarSetCapacity(pbInput,(StrPut(string,encoding)-1)*((encoding ="utf-16"||encoding="cp1200")?2 :1),0)&&cbInput:=StrPut(string,&pbInput,encoding)-1
		if (NT_STATUS:=DllCall("bcrypt\BCryptHashData","ptr",hHash,"ptr",&pbInput,"uint",cbInput,"uint", 0)!= 0)
			throw Exception("BCryptHashData: " NT_STATUS, -1)
		;close the hash
		if (NT_STATUS:=DllCall("bcrypt\BCryptFinishHash","ptr",hHash,"ptr",&pbHash,"uint",cbHash,"uint", 0)!= 0)
			throw Exception("BCryptFinishHash: " NT_STATUS,-1)
		loop % cbHash
			hash.=Format("{:02x}",NumGet(pbHash,a_index-1,"uchar"))
	}
	catch exception
		throw Exception ;represents errors that occur during application execution
	finally
	{	;cleaning up resources
		if (pbInput)
			VarSetCapacity(pbInput,0)
		if (hHash)
			DllCall("bcrypt\BCryptDestroyHash","ptr",hHash)
		if (pbHash)
			VarSetCapacity(pbHash,0)
		if (pbHashObject)
			VarSetCapacity(pbHashObject,0)
		if (hAlg)
			DllCall("bcrypt\BCryptCloseAlgorithmProvider","ptr",hAlg,"uint",0)
		if (hBCRYPT)
			DllCall("FreeLibrary","ptr",hBCRYPT)
	}
	return hash
}

hex2base64(hex)
{	stringleft,n,hex,2
	stringtrimleft,hex,hex,(n="0x")<<1
	stringlen,l,hex
	n:=0,l:=mod(l >> 1,3)
	loop,parse,hex
	{	i:="0x" a_loopfield,n:=i|(n<<4)
		if !mod(a_index,6)
		{	loop 4
				v:=chr(101-a_index),i:=63 & n,n >>= 6
				,%v%:=chr(i<26?i+65:i<52?i+71:i<62?i-4:i=62?43:47)
			if (a_index=6)
				hex:=a b c d
			else hex.=a b c d
		}
	}
	if !(l)
		return hex
	n <<= 3-l << 3
	loop 4
		v:=chr(101-a_index),i:=63&n,n >>= 6
		,%v%:=chr(i<26?i+65:i<52?i+71:i<62?i-4:i=62?43:47)
	return l=1?hex a b "==":hex a b c "="
}

rawurlencode(str)
{	formatinteger:=a_formatinteger
	setformat,integer,h
	stringreplace,str,str,`%,`%25,all
	loop
	{	if regexmatch(str,"i)[^%a-z\d-_\.]",char)
	    {	code:=substr(asc(char),3)
			if strlen(code)<2
				code=0%Code%
			stringupper,code,code
			stringreplace,str,str,%Char%,`%%Code%,all
	    }   else break
	}
	setformat,integer,%formatinteger%
	return str
}

oauth_nonce()
{	
	random, nonce, -2147483648,2147483647 
	return hex2base64(SHA1(a_now a_msec nonce))
} 

;oauth_timestamp()
;{ 	static unixstart:=116444736000000000
;	dllcall("GetSystemTimeAsFileTime","int64p",filetime)
;	return (filetime-unixstart) // 10000000
;}

querybuilder(param_object)
{
	for key, value in param_object {
		queryString.=((a_index="1")?("?"):("&")) key "=" value
	}
	return queryString
}
