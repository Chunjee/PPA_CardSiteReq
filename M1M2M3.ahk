M1()
{	global   
	authorizationProperty =
	(
	OAuth realm="%realm%",  
	oauth_version="%oauth_version%", 
	oauth_timestamp="%oauth_timestamp%", 
	oauth_nonce="%oauth_nonce%",
	oauth_consumer_key="%oauth_consumer_key%", 
	oauth_token="%oauth_token%", 
	oauth_signature_method="%oauth_signature_method%", 
	oauth_signature="%oauth_signature%"
	)
    msgbox % "###" authorizationProperty "###"
	
	url:="https://api.cardmarket.com/ws/v1.1/account"
	WinHTTP.Open("GET",url,0)
	;WinHTTP.SetRequestHeader("Content-Type", "application/x-www-form-urlencoded")
	WinHTTP.SetRequestHeader("Authorization",authorizationProperty)
	WinHTTP.Send()
	WinHTTP.waitforresponse()
	msgbox % WinHTTP.ResponseText
}

M2()
{	global
	options =
	( LTRIM C
		+NO_COOKIES
		+NO_AUTO_REDIRECT
		charset=utf-8
		"METHOD=GET"
	)
	header =
	(
	OAuth realm="https://api.cardmarket.com/ws/v1.1/account",
	oauth_consumer_key="%oauth_consumer_key%",
	oauth_nonce="%oauth_nonce%",
	oauth_signature="%oauth_signature%",
	oauth_signature_method="%oauth_signature_method%",
	oauth_timestamp="%oauth_timestamp%",
	oauth_token="%oauth_token%",
	oauth_version="%oauth_version%"
	)
url:="https://api.cardmarket.com/ws/v1.1/account"
	;url:="https://www.furaffinity.net/login/"
	;msgbox % login_url "`n`n" data "`n`n" headers "`n`n" options
	size:=HTTPRequest(url, data := "", header="", options )
	
	;msgbox % errorlevel "`n" size "`n" header

return

	options:="METHOD=GET"
	header =
	(
	OAuth realm="https://api.cardmarket.com/ws/v1.1/account",
	oauth_consumer_key="%oauth_consumer_key%",
	oauth_nonce="%oauth_nonce%",
	oauth_signature="%oauth_signature%",
	oauth_signature_method="%oauth_signature_method%",
	oauth_timestamp="%oauth_timestamp%",
	oauth_token="%oauth_token%",
	oauth_version="%oauth_version%"
	)

	header2 =
	(	LTRIM C
	OAuth realm="%realm%",
	oauth_consumer_key="%oauth_consumer_key%",
	oauth_token="%oauth_token%",
	oauth_nonce="%oauth_nonce%",
	oauth_timestamp="%oauth_timestamp%",
	oauth_signature_method="%oauth_signature_method%",
	oauth_version="%oauth_version%",
	oauth_signature="%oauth_signature%"
	)

	DST=OAuth realm`="%realm%",oauth_consumer_key`="%oauth_consumer_key%",oauth_token`="%oauth_token%",oauth_nonce`="%oauth_nonce%",oauth_timestamp`="%oauth_timestamp%",oauth_signature_method`="%oauth_signature_method%",oauth_version`="%oauth_version%",oauth_signature`="%oauth_signature%"

	url:="https://api.cardmarket.com/ws/v1.1/account"
	size:=HTTPRequest(url,data :="",DST,options)
	msgbox % errorlevel "`n" data "`n" size "`n" DST
}

M3()
{	global
	;https://api.twitter.com/1.1/statuses/update.json?include_entities=true
	;https://api.cardmarket.com/ws/v1.1/account/update.json?include_entities=true
	/*
	header=
	( 	LTrim Join& 
		Authorization: OAuth realm="%realm%",
		oauth_consumer_key="%APPtoken%",
		oauth_nonce="%oauth_nonce%",
		oauth_signature_method="HMAC-SHA1",
		oauth_timestamp="%oauth_timestamp%",
		oauth_token="%ACCESStoken%",
		oauth_version="1.0",
		oauth_signature="%oauth_signature%"
	)
	*/
	URL:="https://api.cardmarket.com/ws/v1.1/account"
	Credentials:=""
	. "oauth_consumer_key=" APPtoken 
	. "`noauth_consumer_secret=" APPsecret 
	. "`nrealm=" realm
	. "`noauth_token=" ACCESStoken 
	. "`noauth_token_secret=" ACCESStokensecret
	header:=OAuth_Authorization(Credentials,URL)
	;
	size:=httprequest(URL,data="",header)
	msgbox % size "`n" ErrorLevel "`n`n" data "`n`n" header

	
	;https://www.cardmarket.com/en/Magic/MainPage/browseUserProducts?idCategory=1&idUser=17778
	;https://api.cardmarket.com/ws/v2.0/output.json/users/karmacrow/articles	
	;query:=querybuilder({"realm":realm,"oauth_consumer_key":oauth_consumer_key,"oauth_nonce":oauth_nonce,"oauth_signature_method":oauth_signature_method,"oauth_timestamp":oauth_timestamp,"oauth_token":oauth_token,"oauth_version":oauth_version,"oauth_signature":oauth_signature})
	
	;HTTP:=comobjcreate("WinHttp.WinHttpRequest.5.1")
	;HTTP.open("GET",URL)
	;HTTP.SetRequestHeader("Authorization: ","OAuth " query)
	;HTTP.send()
	;HTTP.waitforresponse()
	;msgbox % HTTP.responsetext	
}