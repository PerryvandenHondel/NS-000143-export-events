
Option Explicit


Dim		gsEventLine
Dim		gaEventLine
Dim		x


gsEventLine = "2015-06-19 08:52:01|4624|8|S-1-0-0|-|-|0x0|S-1-5-21-172497072-2655378779-3109935394-53662|Jeroen.Theunis|PROD|0x4352d4cc|3|NtLmSsp |NTLM|VM00AS2420|{00000000-0000-0000-0000-000000000000}|-|NTLM V2|128|0x0|-|10.145.194.47|52311"
gaEventLine = Split(gsEventLine, "|")

For x = 0 To UBound(gaEventLine)
	WScript.Echo x & ":" & vbtab & gaEventLine(x)
Next
WScript.Quit(0)



	