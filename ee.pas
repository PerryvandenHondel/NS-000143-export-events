// ee.pas

//		function ConvertProperDateTimeToDateTimeFs(sDateTime: string): string;
//		function GetPathExport(sEventLog: string; sDateTime: string): string;
//		function GetPathLastRun(sEventLog: string): string;
//		function LastRunGet(sEventLog: string): string;
//		function RunLogparser(sEventLog: string): integer;
//		procedure DoConvert(const sPathLpr: string);
//		procedure ProgDone();
//		procedure ProgInit();
//		procedure ProgRun();
//


program ExportEvents;


{$MODE OBJFPC}


uses
	Crt,
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
	EXTENSION_LPR = 		'.lpr';
	EXTENSION_SKV = 		'.skv';
	MAX_RANDOM_STRING = 	16;


var
	gsComputerName: string;
	gsUniqueSessionId: string;		// Unique session id for this run.
	gsPathPid: string;				// Path of the PID (Process ID) file.
	gbDoConvert: boolean;			//

	
	
function ConvertProperDateTimeToDateTimeFs(sDateTime: string): string;
//
// Convert a proper date time to a date time to be used as a file name (File System).
//
// Converted:	YYYY-MM-DD HH:MM:SS  >> YYYYMMDD-HHMMSS
//
var
	r: string;
begin
	r := StringReplace(sDateTime, '-', '', [rfIgnoreCase, rfReplaceAll]);
	r := StringReplace(r, ':', '', [rfIgnoreCase, rfReplaceAll]);
	r := StringReplace(r, ' ', '-', [rfIgnoreCase, rfReplaceAll]);
	
	ConvertProperDateTimeToDateTimeFs := r;
end; // of function ConvertProperDateTimeToDateTimeFs
	
	
function GetPathExport(sEventLog: string; sDateTime: string): string;
//
// Return a path to an export file in format:
//	folder\computer-eventlog-yyyymmdd-hhmmss-filledwithchars
//
//	sEventLog:		Event log name
//	
//
const
	FILE_NAME_MAX =		16;
var
	r: string;
	//t: string;
begin
	//r := gsComputerName + '-';
	//r := r + sEventLog + '-';
	//r := r + ConvertProperDateTimeToDateTimeFs(sDateTime) + '-';
	
	//t := GetRandomString(FILE_NAME_MAX - Length(r));
	r := GetRandomString(FILE_NAME_MAX);
	 
	//r := r + t;
	GetPathExport := GetProgramFolder() + '\' + r;
end; // of function GetPathExport
	

function GetPathLastRun(sEventLog: string): string;
{
	Create a path fro the lastrun file containing the date time of the last run.
}
begin
	GetPathLastRun := GetProgramFolder() + '\' + gsComputerName + '-' + sEventLog + '.lrd';
end; // of function GetPathLastRun


function LastRunGet(sEventLog: string): string;
{
	Returns the date and time in proper format YYYY-MM-DD HH:MM:SS back from a file in variable sPath
	When the file does not exist, create one, otherwise read the datatime in the file.
}
var
	sPath: string;
	f: TextFile;
	r: string;
begin
	sPath := GetPathLastRun(sEventLog);
	if FileExists(sPath) = true then
	begin
		//WriteLn('LastRunGet(): Read the line with the last date time from ' + sPath);
		AssignFile(f, sPath);
		{I+}
		// Open the file in read mode.
		Reset(f);
		ReadLn(f, r);
		CloseFile(f);
	end
	else
	begin
		//WriteLn('LastRunGet(): File ' + sPath + ' not found create a new file');
		
		AssignFile(f, sPath);
		{I+}
		// Open the file in write mode.
		ReWrite(f);
		r := GetProperDateTime(Now());
		WriteLn(f, r);
		CloseFile(f);
	end;
	LastRunGet := r;
end;


function LastRunPut(sEventLog: string): string;
{
	Put the current date time using Now() in the file sPath.
}
var
	sPath: string;
	f: TextFile;
	r: string;
begin
	sPath := GetPathLastRun(sEventLog);
	if FileExists(sPath) = true then
	begin
		AssignFile(f, sPath);
		{I+}
		// Open the file in write mode.
		ReWrite(f);
		r := GetProperDateTime(Now());
		WriteLn(f, r);
		CloseFile(f);
	end
	else
	begin
		WriteLn('ERROR LastRunPut(): can''t find the file ' + sPath);
	end;
	LastRunPut := r;
end; // of function LastRunPut.


function RunLogparser(sPathLpr: string; sEventLog: string): integer;
//
//	Run Logparser.exe for a specfic Event Log.
//
//	sEventLog:		Name of Event Log to export.
//
var
	p: TProcess;	// Process
	c: AnsiString;		// Command Line
	sDateTimeLast: string;
	sDateTimeNow: string;
	
begin
	WriteLn;
	//WriteLn('RunLogparser(): ' + sEventLog);

	sDateTimeLast := LastRunGet(sEventLog);
	sDateTimeNow := LastRunPut(sEventLog);
	//sPath := GetPathExport(sEventLog, sDateTimeLast);
	
	
	WriteLn('RunLogparser(): Exporting events from ''' + sEventLog + ''' with date time range from ' + sDateTimeLast + ' - ' + sDateTimeNow + ' into export file ''' + sPathLpr + '''.');
	
	//WriteLn('sDateTimeLast=', sDateTimeLast);
	//WriteLn('sDateTimeNow=', sDateTimeNow);
	//WriteLn('sPathLpr=', sPathLpr);
	
	// logparser.exe -i:EVT -o:TSV 
	// "SELECT TimeGenerated,EventId,EventType,REPLACE_STR(Strings,'\u000d\u000a','|') AS Strings FROM \\NS00DC066\Security WHERE TimeGenerated>'2015-06-02 13:48:00' AND TimeGenerated<='2015-06-02 13:48:46'" -stats:OFF -oSeparator:"|" 
	// >"D:\ADBEHEER\Scripts\000134\export\NS00DC066\20150602-134800-72Od1Q7jYYJsZqFW.lpr"

	c := 'logparser.exe -i:EVT -o:TSV ';
	c := c + '"SELECT TimeGenerated,EventId,EventType,REPLACE_STR(Strings,''\u000d\u000a'',''|'') AS Strings ';
	c := c + 'FROM '+ sEventLog + ' ';
	c := c + 'WHERE TimeGenerated>''' + sDateTimeLast + ''' AND TimeGenerated<=''' + sDateTimeNow + '''" ';
	c := c + '-stats:OFF -oSeparator:"|" ';
	c := c + '>' + sPathLpr;
	
	WriteLn('Running:');
	WriteLn;
	WriteLn(c);
	WriteLn;
	
	// Setup the process to be executed.
	p := TProcess.Create(nil);
	p.Executable := 'cmd.exe'; 
    p.Parameters.Add('/c ' + c);
	p.Options := [poWaitOnExit];
	
	// Run the sub process.
	p.Execute;
	
	RunLogparser := p.ExitStatus;
end; // of procedure RunLogparser


procedure DoConvert(const sPathLpr: string);
var
	sPathSkv: string;
begin
	WriteLn('DoConvert(): ' + sPathLpr);
	
	sPathSkv := StringReplace(sPathLpr, EXTENSION_LPR, EXTENSION_SKV, [rfIgnoreCase, rfReplaceAll]);
	WriteLn('sPathSkv=' + sPathSkv);
	WriteLn;
end;


procedure ProgTest();
begin
	DoConvert('R:\GitRepos\NS-000143-export-events\OYFQzMNkWIh1UGio.lpr');
end;
	
	
procedure ProgInit();
begin
	// Get the computer name of where this program is running.
	gsComputerName := GetCurrentComputerName();
	
	// Generate a unique session ID for this run of the program.
	gsUniqueSessionId := GetRandomString(MAX_RANDOM_STRING);
	
	// Create a PID (Process ID) file for the run of this program.
	gsPathPid := GetPathOfPidFile();
	
	
	gbDoConvert := true;
end; // of procedure ProgInit()


procedure ProgRun();
var
	sPathLpr: string;
	iResultLogparser: integer;
	iFileSize: integer;
begin
	//WriteLn(GetPathOfPidFile());
	
	sPathLpr := GetProgramFolder + '\' + gsUniqueSessionId + EXTENSION_LPR;
	iResultLogparser := RunLogparser(sPathLpr, 'Security');
	if iResultLogparser = 0 then
	begin
		iFileSize := GetFileSizeInBytes(sPathLpr);
		if iFileSize > 0 then
		begin
			WriteLn('Logparser output file ' + sPathLpr + ' contains data, start converting.');
			
			
			if gbDoConvert = true then
				DoConvert(sPathLpr);
			
		end
		else
		begin
			WriteLn('Logparser output file ' + sPathLpr + ' is empty');
			// Delete the empty file.
			DeleteFile(sPathLpr);
		end; // of if iFileSize
	end // of if iResultLogparser
	else
	begin
		WriteLn('ERROR running Logparser, error: ', iResultLogparser);
	end;
	//WriteLn(GetPathLastRun('Security'));
	//WriteLn('LAST RUN GET = ', LastRunGet('Security'));
	//WriteLn('LAST RUN PUT = ', LastRunPut('Security'));
	
	//WriteLn(ConvertProperDateTimeToDateTimeFs('2015-06-11 12:09:56'));
	//WriteLn(GetPathExport('Security', '2015-06-11 12:09:56'));
end; // of procedure ProgRun()


procedure ProgDone();
begin
	// Delete the Process ID file.
	DeleteFile(gsPathPid);
end; // of procedure ProgDone()


begin
	ProgInit();
	//ProgRun();
	ProgTest();
	ProgDone();
end. // of program ExportEvents