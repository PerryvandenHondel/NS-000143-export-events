// ee.pas

program ExportEvents;


{$MODE OBJFPC}


uses
  Classes, 
  Process, 
  SysUtils,
  USupportLibrary;
  
  
const
	CHAR_TAB = 				#9;
	CHAR_CR =				#13;
	CHAR_LF = 				#10;
	CRLF = 					#13#10;
	VERSION =				'01';
	DESCRIPTION =			'ExportEvents';
	ID = 					'143';		


function RunLogparser(): integer;
//
//	Run Logparser.exe
//
var
	p: TProcess;	// Process
	c: string;		// Command Line
begin
	WriteLn;
	WriteLn('RunLogparser()');

	// logparser.exe -i:EVT -o:TSV 
	// "SELECT TimeGenerated,EventId,EventType,REPLACE_STR(Strings,'\u000d\u000a','|') AS Strings FROM \\NS00DC066\Security WHERE TimeGenerated>'2015-06-02 13:48:00' AND TimeGenerated<='2015-06-02 13:48:46'" -stats:OFF -oSeparator:"|" 
	// >"D:\ADBEHEER\Scripts\000134\export\NS00DC066\20150602-134800-72Od1Q7jYYJsZqFW.lpr"

	c := 'logparser.exe -i:EVT -o:TSV ';
	c := c + '"SELECT TimeGenerated,EventId,EventType,REPLACE_STR(Strings,''\u000d\u000a'',''|'') AS Strings ';
	c := c + 'FROM Security WHERE TimeGenerated>''2015-06-11 12:00:00'' AND TimeGenerated<=''2015-06-11 13:00:00''" ';
	c := c + '-stats:OFF -oSeparator:"|" ';
	c := c + '>out.lpr';
	
	
	WriteLn;
	WriteLn(c);
	WriteLn;
	
	p := TProcess.Create(nil);
	p.Executable := 'cmd.exe'; 
    p.Parameters.Add('/c ' + c);
	p.Options := [poWaitOnExit];

	//p.Execute;
	
	RunLogparser := p.ExitStatus; 
end; // of procedure GetAllDomainTrusts
	
	
	
	
procedure ProgInit();
begin
end; // of procedure ProgInit()


procedure ProgRun();
begin
	WriteLn('RUNLOGPARSER() RETURNS: ', RunLogparser());
end; // of procedure ProgRun()


procedure ProgDone();
begin
end; // of procedure ProgDone()


begin
	ProgInit();
	ProgRun();
	ProgDone();
end. // of program ExportEvents