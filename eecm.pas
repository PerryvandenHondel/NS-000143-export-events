{
	PROGRAM:
		export-events-and-convert-for-splunk
		
	STEPS:
		1) Export Events with Logparser.exe.
		2) Convert Logparser output (LPR) to Splunk Key-Values (SKV) file.
		3) Transfer both generated files, LPR for archiving and SKV for indexing, to the Splunk server.

	PROCEDURES AND FUNCTIONS:
		function ConvertProperDateTimeToDateTimeFs(sDateTime: string): string
		function GetEventType(eventType: integer): string
		function GetKeyName(eventId: integer; position: integer): string
		function GetKeyType(eventId: integer; position: integer): boolean
		function GetPathExport(sEventLog: string; sDateTime: string): string
		function GetPathLastRun(sEventLog: string): string
		function LastRunGet(sEventLog: string): string
		function ProcessThisEvent(e: integer): boolean
		function RobocopyMove(const sPathSource: string; sFolderDest: string): integer;
		function RunLogparser(sEventLog: string): integer
		procedure DoConvert(const sPathLpr: string)
		procedure EventDetailRecordAdd(newEventId: integer; newKeyName: string; newPostion: integer; newIsString: boolean)
		procedure EventFoundAdd(newEventId: integer)
		procedure EventFoundStats()
		procedure EventIncreaseCount(SearchEventId: word)
		procedure EventRecordAdd(newEventId: word; newDescription: string; newOsVersion: word)
		procedure EventRecordShow()
		procedure MoveOutput(const sPathLpr: string; const sPathSkv: string)
		procedure ProcessEvent(eventId: integer; la: TStringArray)
		procedure ProcessLine(lineCount: integer; l: AnsiString)
		procedure ProgDone()
		procedure ProgInit()
		procedure ProgRun()
		procedure ReadEventDefinitionFile(p : string)
		procedure ReadEventDefinitionFiles()
		procedure ShowStatistics()
		procedure WriteDebug(s : string)

	PROGRAM FLOW:
		ProgInit
		ProgRun
			RunLogparser
			DoConvert
				ReadEventDefinitionFiles
					ReadEventDefinitionFile
				ProcessEvent
					ProcessLine
				ShowStatistics	
			MoveOutput
				RobocopyMove
		ProgDone
		
}


program ExportEvents;


{$MODE OBJFPC}


uses
	Crt,
	Classes, 
	DateUtils,						// For SecondsBetween
	Process, 
	SysUtils,
	USupportLibrary,
	UTextFile;
  
 
const
	TAB = 						#9;
	CHAR_CR =					#13;
	CHAR_LF = 					#10;
	CRLF = 						#13#10;
	VERSION =					'01';
	DESCRIPTION =				'ExportEvents';
	ID = 						'143';
	EXTENSION_LPR = 			'.lpr';
	EXTENSION_SKV = 			'.skv';
	MAX_RANDOM_STRING = 		16;
	SEPARATOR_CSV = 			';';			// Semicolon (;)
	SEPARATOR_PSV = 			'|';			// Pipe Separator symbol (|)
	STEP_MOD =					127;			// Step modulator for echo mod, use a off-number, not rounded as 10, 15, 100, 250 etc. to see the changes.
	SHARE_LPR = 				'\\vm70as006.rec.nsint\GARBAGE';
	SHARE_SKV = 				'\\vm70as006.rec.nsint\GARBAGE';
	
	
type
	// Type definition of the Event Records
	TEventRecord = record
		eventId: integer;
		description: string;
		count: integer;
		osVersion: word;
	end;
	TEventArray = array of TEventRecord;

	TEventDetailRecord = record
		eventId: integer;           // Event number
		keyName: string;            // Key name under Splunk
		position: word;       	   	// Position in the Logparser string
		isString: boolean;          // Save value as string (True=String, False=number)
	end;
    TEventDetailArray = array of TEventDetailRecord;
	

var
	gsComputerName: string;
	gsUniqueSessionId: string;		// Unique session id for this run.
	gsPathPid: string;				// Path of the PID (Process ID) file.
	gbDoConvert: boolean;			//
	EventDetailArray: TEventDetailArray;
	EventArray: TEventArray;
	tfLpr: CTextFile;
	tfSkv: CTextFile;
	blnDebug: boolean;
	blnSkipComputerAccount: boolean;
	intCountAccountComputer: longint;


procedure WriteDebug(s : string);
begin
	if blnDebug = true then
		Writeln('DEGUG:', Chr(9), s);
end;  // of procedure WriteDebug	
	
	
procedure ShowStatistics();
const
	W_EVENT = 10;
	W_COUNT = 10;
	W_DESC = 50;
	
var
	i: integer;
	totalEvents: integer;
begin
	totalEvents := 0;
	
	WriteLn();
	
	WriteLn('STATISTICS:');
	//tfLog.WriteToFile('STATISTICS:');
	
	WriteLn();
	//tfLog.WriteToFile('');
	
	WriteLn(AlignLeft('Event ID:', W_EVENT) + ' ' + AlignLeft('Amount:', W_COUNT) + ' ' +  AlignLeft('Event Description:', W_DESC));
	WriteLn(StringOfChar('-', W_EVENT) + ' ' + StringOfChar('-', W_COUNT) + ' ' + StringOfChar('-', W_DESC));
	
	//tfLog.WriteToFile('Evt' + Chr(9) + 'Number' + Chr(9) + 'Description');
	
	//tfLog.WriteToFile('----' + Chr(9) + '------' + Chr(9) + '--------------------------------------');
	
	for i := 0 to High(EventArray) do
	begin
		//WriteLn('record: ' + IntToStr(i));
		WriteLn(AlignRight(EventArray[i].eventId, W_EVENT) + ' ' + AlignRight(EventArray[i].count, W_COUNT) + ' ' + AlignLeft(EventArray[i].description, W_DESC));
		//Writeln(EventArray[i].eventId:4, Chr(9), EventArray[i].count:6, Chr(9), EventArray[i].description, ' (', EventArray[i].osVersion, ')');
		//tfLog.WriteToFile(IntToStr(EventArray[i].eventId) + Chr(9) + IntToStr(EventArray[i].count) + Chr(9) + EventArray[i].description + ' (' + IntToStr(EventArray[i].osVersion) + ')');
		
		totalEvents := totalEvents + EventArray[i].count;
	end;
	WriteLn;
	//tfLog.WriteToFile('');
	
	WriteLn('Total of events ', totalEvents, ' converted.');
	if blnSkipComputerAccount = true then
	begin
		Writeln('Skipped ', intCountAccountComputer, ' computer accounts');
	end;
	
	//tfLog.WriteToFile('Total of events ' +  IntToStr(totalEvents) + ' converted.');
	
	WriteLn;
end; // of procedure ShowStatistics

	
function GetKeyName(eventId: integer; position: integer): string;
{
	Returns the KeyName of a valid position
}
var
	i: integer;
	r: string;
begin
	r := '';
	//WriteLn('GetKeyName(', eventId, ',', position, ')');
	
	for i := 0 to High(EventDetailArray) do
	begin
		if (eventId = EventDetailArray[i].eventId) then
		begin
			//WriteLn(Chr(9), IntToStr(EventDetailArray[i].position));
			if position = EventDetailArray[i].position then
			begin
				r := EventDetailArray[i].keyName;
				//if EventDetailArray[i].isActive = true then
				//begin
					//WriteLn('FOUND FOR EVENTID ', eventId, ' AND ACTIVE KEYNAME ON POSITION ', position);
				//end;
			end;
		end;
	end;
	GetKeyName := r;
end; // of function GetKeyName


procedure EventIncreaseCount(SearchEventId: word);
var
	newCount: integer;
	i: integer;
begin
	for i := 0 to High(EventArray) do
	begin
		if EventArray[i].eventId = SearchEventId then
		begin
			newCount := EventArray[i].count + 1;
			EventArray[i].count := newCount
		end; // of procedure EventIncreaseCount
	end;
end; // of procedure EventIncreaseCount


function GetEventType(eventType: integer): string;
{
	Returns the Event Type string for a EventType

	1		ERROR
	2		WARNING
	3		INFO
	4		SUCCESS	AUDIT
	5		FAILURE AUDIT
	
	Source: https://msdn.microsoft.com/en-us/library/aa394226%28v=vs.85%29.aspx
}	
var
	r: string;
begin
	r := '';
	
	case eventType of
		1: r := 'ERR';	// Error
		2: r := 'WRN';	// Warning
		4: r := 'INF';	// Information
		8: r := 'AUS';	// Audit Success
		16: r := 'AUF';	// Audit Failure
	else
		r := 'UKN';		// Unknown Note: should never be seen.
	end;
	GetEventType := r;
end; // of function GetEventType


function GetKeyType(eventId: integer; position: integer): boolean;
{
	Returns the KeyType of a valid position
}
var
	i: integer;
	r: boolean;
begin
	r := false;
	//WriteLn('GetKeyName(', eventId, ',', position, ')');
	
	for i := 0 to High(EventDetailArray) do
	begin
		if (eventId = EventDetailArray[i].eventId) then
		begin
			//WriteLn(Chr(9), IntToStr(EventDetailArray[i].position));
			if position = EventDetailArray[i].position then
				r := EventDetailArray[i].isString;
			//begin
				//if EventDetailArray[i].isActive = true then
				//begin
					//WriteLn('FOUND FOR EVENTID ', eventId, ' AND ACTIVE KEYNAME ON POSITION ', position);
				//end;
			//end;
		end;
	end;
	GetKeyType := r;
end; // of function GetKeyType	
	
	
procedure EventRecordShow();
var
	i: integer;
begin
	WriteLn();
	WriteLn('Events to process:');

	for i := 0 to High(EventArray) do
	begin
		//Writeln(IntToStr(i) + Chr(9) + ' ' + IntToStr(EventArray[i].eventId) + Chr(9), EventArray[i].isActive, Chr(9) + IntToStr(EventArray[i].osVersion) + Chr(9) + EventArray[i].description);
		Writeln(AlignRight(i, 6) + AlignRight(EventArray[i].eventId, 6) + AlignRight(EventArray[i].osVersion, 6) + '  ' + EventArray[i].description);
	end;
end; // of procedure EventRecordShow	


function RobocopyMove(const sPathSource: string; sFolderDest: string): integer;
{
	Use Robocopy.exe to move a file.
	Create folders that are needed is done by Robocopy.
	
		sPathSource			D:\folder\folder\file.ext
		sFolderDest			D:\foldernew
	
	Returns the errorlevel of robocopy execution
	An errorlevel > 15 is an error.
}
var
	p: TProcess;
	c: string;
	sFilename: string;
	sFolderSource: string;
	r: integer;
begin
	if FileExists(sPathSource) = true then
	begin
		sFilename := ExtractFileName(sPathSource);
		sFolderSource := FixFolderRemove(ExtractFilePath(sPathSource));
		sFolderDest := FixFolderRemove(sFolderDest);

		WriteLn('ROBOCOPYMOVE()');
		WriteLn('  Moving file: ', sFilename);
		WriteLn('  from folder: ', sFolderSource);
		WriteLn('    to folder: ', sFolderDest);
	
		c := 'robocopy.exe ' + EncloseDoubleQuote(sFolderSource) + ' ' + EncloseDoubleQuote(sFolderDest) + ' ' + EncloseDoubleQuote(sFilename) + '" /mov /tee /log:robocopy.log';
	
		WriteLn;
		WriteLn('Command:');
		WriteLn(c);
		WriteLn;
		
		// Setup the process to be executed.
		p := TProcess.Create(nil);
		p.Executable := 'cmd.exe'; 
		p.Parameters.Add('/c ' + c);
		p.Options := [poWaitOnExit];
	
		// Run the sub process.
		p.Execute;
	
		r := p.ExitStatus;
	end
	else
	begin
		WriteLn('RobocopyMove(): Warning, can''t find file ', sPathSource);
	end;
	RobocopyMove := r;
end; // of function RobocopyMove.


procedure MoveOutput(const sPathLpr: string; const sPathSkv: string);
{
	Move the LPR and SKV files to the shares on the Splunk server.
}
var
	sFolderDest: string;
	e: integer;
begin
	WriteLn('MoveOutput():');
	WriteLn(' sPathLpr=', sPathLpr);
	WriteLn(' sPathSkv=', sPathSkv);
	
	sFolderDest := FixFolderAdd(SHARE_LPR) + '999999\' + GetDateFs(true) + '\' + GetCurrentComputerName();
	e := RobocopyMove(sPathLpr, sFolderDest);
	if e > 15 then
		WriteLn('ERROR ', e, ' during moving of file ', sPathLpr, ' to ', sFolderDest)
	else
		WriteLn('Succesfully moved ', sPathLpr);
	
	
	sFolderDest := FixFolderAdd(SHARE_SKV) + '999999\' + GetDateFs(true) + '\' + GetCurrentComputerName();
	e := RobocopyMove(sPathSkv, sFolderDest);
	if e > 15 then
		WriteLn('ERROR ', e, 'during moving of file ', sPathSkv, ' to ', sFolderDest)
	else
		WriteLn('Succesfully moved ', sPathSkv);
end; // of procedure MoveOutput.


procedure EventDetailRecordAdd(newEventId: integer; newKeyName: string; newPostion: integer; newIsString: boolean); // V06
{
		
	EventId;KeyName;Position;IsString;IsActive

	Add a new record in the array of EventDetail
  
	newEventId      integer		The event id to search for
	newKeyName  	string		Description of the event
	newPostion  	integer		Integer of version 2003/2008
	newIsString		boolean		Is this a string value
									TRUE	Process as an string
									FALSE	Process this as an number
	newIsActive		boolean		Is tris an active event detail; 
									TRUE=process this 
									FALSE = Do not process this
}
var
	size: integer;
begin
	size := Length(EventDetailArray);
	SetLength(EventDetailArray, size + 1);
	EventDetailArray[size].eventId := newEventId;
	EventDetailArray[size].keyName := newKeyName;
	EventDetailArray[size].position := newPostion;
	EventDetailArray[size].isString := newIsString;
	//EventDetailArray[size].isActive := newIsActive;
	//EventDetailArray[size].convertAction := newConvertAction;
	
end; // of procedure EventDetailRecordAdd

	
procedure EventRecordAdd(newEventId: word; newDescription: string; newOsVersion: word); // V06
{

	EventId;Description;OsVersion;IsActive

	Add a new record in the array of Event
  
	newEventId      word		The event id to search for
	newDescription  string		Description of the event
	newOsVersion    integer		Integer of version 2003/2008
	newIsActive		boolean		Is this an active event, 
									TRUE	Process this event.
									FALSE	Do not process this event.
									
}
var
	size: integer;
begin
	size := Length(EventArray);
	SetLength(EventArray, size + 1);
	EventArray[size].eventId := newEventId;
	EventArray[size].osVersion := newOsVersion;
	EventArray[size].description := newDescription;
	EventArray[size].count := 0;
	//EventArray[size].isActive := newIsActive;
end; // of procedure EventRecordAdd
	
	
procedure ReadEventDefinitionFile(p : string);
var
	//strEvent: string;
	//intEvent: integer;
	//strFilename: string;
	tf: CTextFile; 		// Text File
	l: string;			// Line Buffer
	x: integer;			// Line Counter
	a: TStringArray;	// Array
begin
	//WriteLn('ReadEventDefinitionFile: ==> ', p);
	
	//WriteLn(ExtractFileName(p)); // Get the file name with the extension.
	
	// Get the file name from the path p.
	//strFilename := ExtractFileName(p);
	
	//WriteLn(ExtractFileExt(p));
	// Get the event id from the file name by removing the extension from the file name.
	//strEvent := ReplaceText(strFilename, ExtractFileExt(p), '');
	
	//WriteLn(strEvent);
	// Convert the string with Event ID to a integer.
	//intEvent := StrToInt(strEvent);
	//WriteLn(intEvent);
	
	
	
	//WriteLn('CONTENTS OF ', p);
	tf := CTextFile.Create(p);
	tf.OpenFileRead();
	repeat
		l := tf.ReadFromFile();
		If Length(l) > 0 Then
		begin
			//WriteLn(l);
			x := tf.GetCurrentLine();
			a := SplitString(l, SEPARATOR_CSV);
			if x = 1 then
			begin
				//WriteLn('FIRST LINE!');
				//WriteLn(Chr(9), l);
				//EventRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2]), StrToBool(a[3])); // V05
				EventRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2])); // V06
			end
			else
			begin
				//WriteLn('BIGGER > 1');
				//WriteLn(Chr(9), l);
				//EventDetailRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2]), StrToBool(a[3]), StrToBool(a[4]), a[5]); // V05
				EventDetailRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2]), StrToBool(a[3])); // V06
			end;
			//WriteLn(x, Chr(9), l);
		end;
	until tf.GetEof();
	tf.CloseFile();
	
	//WriteLn;
end; // of procedure ReadEventDefinitionFile


procedure ReadEventDefinitionFiles();
{
	Read the .EVD files and place the values is an array.
}
var	
	sr : TSearchRec;
	count : Longint;
begin
	count:=0;
	
	SetLength(EventArray, 0);
	SetLength(EventDetailArray, 0);
	
	if FindFirst(GetProgramFolder() + '\*.evd', faAnyFile and faDirectory, sr) = 0 then
    begin
    repeat
		Inc(count);
		with sr do
		begin
			ReadEventDefinitionFile(GetProgramFolder() + '\' + name);
        end;
		until FindNext(sr) <> 0;
    end;
	FindClose(sr);
	Writeln ('Found ', count, ' event definitions to process.');
end; // of procedure ReadAllEventDefinitions	
	
	
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
	
	
	WriteLn('RunLogparser():');
	WriteLn('  Exporting events from Event Log : ' + sEventLog);
	WriteLn('                        from date : ' + sDateTimeLast);
	WriteLn('                             upto : ' + sDateTimeNow);
	Writeln('                 into export file : ' + sPathLpr);
	
	//WriteLn('SECONDS=', SecondsBetween(StrToDateTime(sDateTimeLast), StrToDateTime(sDateTimeNow)));
	
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


procedure ProcessEvent(eventId: integer; la: TStringArray);
var
	x: integer;
	strKeyName: string;
	s: string;
	buffer: AnsiString;
	intPosDollar: integer;		// Position of dollar sign in computer name
	intPosAccount: integer;		// Position of acc key name
begin
	WriteDebug('-----------------------');
	WriteDebug('ProcessEvent(): ' + IntToStr(eventId));
	buffer := la[0] + ' ' + GetEventType(StrToInt(la[2])) + ' eid=' + IntToStr(eventId) + ' ';
	
	//EventFoundAdd(eventId);
	
	// Testing
	{
	for x := 0 To High(la) do
	begin
		WriteLn('ProcessEvent():', Chr(9), Chr(9), x, ':', Chr(9), la[x]);
	end;
	}
	
	for x := 0 to High(la) do
	begin
		//WriteLn(Chr(9), x, Chr(9), eventId, Chr(9), la[x]);
		strKeyName := GetKeyName(eventId, x);
		if Length(strKeyName) > 0 then
		begin
			s := GetKeyName(eventId, x);
			s := s + '=';
			if GetKeyType(eventId, x) = true then
				s := s + Chr(34) + la[x] + Chr(34)
			else
				s := s + la[x];
			
			WriteDebug('KeyValue:' + s);
			
			// Check for key field 'acc' and dollar sign in value
			intPosDollar := Pos('$"', s);
			intPosAccount := Pos('acc=', s);
						
			WriteDebug('intPosDollar=' + IntToStr(intPosDollar));
			WriteDebug('intPosAccount=' + IntToStr(intPosAccount));
			WriteDebug('blnSkipComputerAccount=' + BoolToStr(blnSkipComputerAccount));
			
			if (intPosDollar > 0) and (intPosAccount > 0) and (blnSkipComputerAccount = true) then
			begin	
				WriteDebug('DO NOT WRITE THIS LINE');
				Inc(intCountAccountComputer);
				Exit; // Exit function ProcessEvent
			end;
			
			buffer := buffer + s + ' ';
		end;
	end; // of for x := 0 to High(la) do
	
	// Update the counter of processed events.
	EventIncreaseCount(eventId);
	
	tfSkv.WriteToFile(buffer);
end; // of function ProcessEvent




function ProcessThisEvent(e: integer): boolean;
{
	Read the events from the EventArray.
	Return the status for isActive.
	
	Returns
		TRUE		Process this event.
		FALSE		Do not process this event.
}
var
	i: integer;
	r: boolean;
begin
	r := false;
	
	//WriteLn;
	//WriteLn('ProcessThisEvent(): e=', e);
	for i := 0 to High(EventArray) do
	begin
		//WriteLn(i, chr(9), EventArray[i].eventId, Chr(9), EventArray[i].isActive);
		if EventArray[i].eventId = e then
		begin
			r := true;
			//WriteLn('FOUND ', e, ' ON POS ', i);
			break;
			// Found the event e in the array, return the isActive state
			//r := EventArray[i].isActive;
			//break;
		end;
	end;
	//WriteLn('ShouldEventBeProcessed():', Chr(9), e, Chr(9), r);
	ProcessThisEvent := r;
end;


procedure ProcessLine(lineCount: integer; l: AnsiString);
{
	Process a line 
}
var
	lineArray: TStringArray;
	eventId: integer;
begin
	if Pos('TimeGenerated|', l) > 0 then
		Exit;	//	When the text 'TimeGenerated|' occurs in the line it's a header line, skip it by exiting this procedure.
		
	if Length(l) > 0 then
	begin
		//WriteLn(lineCount, ' ', l);

		// Set the lineArray on 0 to clear it
		SetLength(lineArray, 0);
		
		// Split the line into the lineArray
		lineArray := SplitString(l, SEPARATOR_PSV);
		
		// Obtain the eventId from the lineArray on position 4.
		eventId := StrToInt(lineArray[1]);	// The Event Id is always found at the 1st position
		//Writeln(lineCount, Chr(9), l);
		//WriteLn(Chr(9), eventId);
		
		if ProcessThisEvent(eventId) = true then
		begin
			// Write only the events to the SKV file that have a EVD (Event Definition) file present.
			ProcessEvent(eventId, lineArray);
		end;
		SetLength(lineArray, 0);
	end; // if Length(l) > 0 then
end; // of procedure ProcessLine()


procedure DoConvert(const sPathLpr: string; const sPathSkv: string);
{
	Do a file conversion of a Logparser export (lpr) to a Splunk Key-Values (skv) file.
}
var
	intCurrentLine: integer;		// Line counter
	strLine: AnsiString;			// Buffer for the read line, can be longer then 255 chars so AnsiString;
begin
	WriteLn('DoConvert(): ' + sPathLpr);
	
	// Read all event definition files in the array.
	ReadEventDefinitionFiles();
	// Debug
	EventRecordShow();
	
	// Delete any existing output Splunk SKV file.
	if FileExists(sPathSkv) = true then
	begin
		//WriteLn('WARNING: File ' + pathSplunk + ' found, deleted it.');
		DeleteFile(sPathSkv);
	end;
	
	tfSkv := CTextFile.Create(sPathSkv);
	tfSkv.OpenFileWrite();
	
	tfLpr := CTextFile.Create(sPathLpr);
	tfLpr.OpenFileRead();
	repeat
		strLine := tfLpr.ReadFromFile();
		intCurrentLine := tfLpr.GetCurrentLine();
		//WriteLn(intCurrentLine, Chr(9), strLine);
		
		ProcessLine(intCurrentLine, strLine);
		//WriteLn(intCurrentLine, '|', strLine);
			
		WriteMod(intCurrentLine, STEP_MOD); // In USupport Library
	until tfLpr.GetEof();
	tfLpr.CloseFile();
	
	tfSkv.CloseFile();
	
	//EventFoundStats();
end;


procedure ProgTest();
begin
	//DoConvert('R:\GitRepos\NS-000143-export-events\jgiXefFeh9bwcdDL.lpr');
	//DoConvert('R:\GitRepos\NS-000143-export-events\Bf0WY9jupV3UgT92.lpr');
	
	{
	//WriteLn('                                                                                                   1');
	WriteLn('         1         2         3         4         5         6         7         8         9         0');
	WriteLn('1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890');
	WriteLn(AlignRight('Aligment right test', 80));
	WriteLn(AlignRight(1832644, 80));
	
	WriteLn(AlignRight('Aligmen jhksgkj afgkjhafd gjkha gfdjhk ajkgdft test', 20));
	WriteLn(AlignLeft('Aligment left test', 80) + 'THE NEXT TEXT');
	WriteLn(AlignLeft(176543, 80) + 'THE NEXT TEXT');
	}
	//MoveOutput('R:\GitRepos\NS-000143-export-events\HbOSZUtfvvsBWn86.lpr', 'R:\GitRepos\NS-000143-export-events\HbOSZUtfvvsBWn86.skv');
	
	//WriteLn(FixFolderRemove('R:\folder\folder\folder'));
	//WriteLn(FixFolderRemove('R:\folder\folder\'));
	
	//WriteLn(FixFolderAdd('R:\folder\folder\folder'));
	//WriteLn(FixFolderAdd('R:\folder\folder\'));
	
	WriteLn(EncloseDoubleQuote('test string1'));
	WriteLn(EncloseDoubleQuote('"test string2'));
	WriteLn(EncloseDoubleQuote('test string3"'));
	WriteLn(EncloseDoubleQuote('"test string4"'));
	
end;
	
	
procedure ProgramUsage();
var
	sProgName: string;
begin
	sProgName := GetProgramName();
	WriteLn;
	WriteLn('Usage:');
	WriteLn('  ' +sProgName + ' [option(s)]');
	WriteLn;
	WriteLn('Options:');
	WriteLn('  --convert-skv                  Convert the output to Splunk Key-Values format (created a .SKV file).');
	WriteLn('  --include-computer-accounts    Include the computer accounts (COMPUTERNAME$) in the Splunk output');
	WriteLn('  --help, -h, -?                 Help');
	WriteLn;
	WriteLn('Example:');
	WriteLn('  ' + sProgName + '                       Export but doe not convert to Splunk Key-Values output, missing --convert-skv option');
	WriteLn('  ' + sProgName + ' --convert-skv         Export and convert to Splunk Key-Values output');
	WriteLn;
end; // of procedure ProgramUsage()


procedure ProgramTitle();
begin
	WriteLn();
	WriteLn(StringOfChar('-', 120));
	WriteLn(UpperCase(GetProgramName()) + ' -- Version: ' + VERSION + ' -- Unique ID: ' + ID);
	WriteLn();
	WriteLn(DESCRIPTION);
	WriteLn(StringOfChar('-', 120));	
end; // of procedure ProgramTitle()


procedure ProgDone();
begin
	// Delete the Process ID file.
	DeleteFile(gsPathPid);
	Halt(0);
end; // of procedure ProgDone()

	
procedure ProgInit();
var
	i: integer;
begin
	ProgramTitle();

	// Get the computer name of where this program is running.
	gsComputerName := GetCurrentComputerName();
	
	// Generate a unique session ID for this run of the program.
	gsUniqueSessionId := GetRandomString(MAX_RANDOM_STRING);
	
	// Create a PID (Process ID) file for the run of this program.
	gsPathPid := GetPathOfPidFile();
	
	// Dot not convert the LPR file to SKV.
	gbDoConvert := false;
	
	blnSkipComputerAccount := true;
	blnDebug := false;
	
	// Initialize the Event count array.
	//SetLength(EventFound, 1);
	
	if ParamCount > 0 then
	begin
		for i := 1 to ParamCount do
		begin
			//Writeln(i, ': ', ParamStr(i));
			
			case LowerCase(ParamStr(i)) of
				'--convert-skv':
					begin
						gbDoConvert := true;
						WriteLn('Option selected to convert the output to Splunk Key-Values (SKV) layout format');
					end;
				'--include-computer-accounts':
					begin
						blnSkipComputerAccount := false;
						WriteLn('Option selected to include computer accounts in the Splunk conversion.');
					end;
				'--help', '-h', '-?':
					begin
						ProgramUsage();
						ProgDone()
					end;
			end; // of case
		end; // of for
	end;
end; // of procedure ProgInit()


procedure ProgRun();
var
	sPathLpr: string;
	iResultLogparser: integer;
	iFileSize: integer;
	sPathSkv: string;
begin
	//WriteLn(GetPathOfPidFile());
	
	sPathLpr := GetProgramFolder + '\' + gsUniqueSessionId + EXTENSION_LPR;
	
	// STEP 1 Export
	iResultLogparser := RunLogparser(sPathLpr, 'Security');
	if iResultLogparser = 0 then
	begin
		iFileSize := GetFileSizeInBytes(sPathLpr);
		if iFileSize > 0 then
		begin
			WriteLn('Logparser output file ' + sPathLpr + ' contains data, start converting.');
			
			// Build the path to the SKV output file.
			sPathSkv := StringReplace(sPathLpr, EXTENSION_LPR, EXTENSION_SKV, [rfIgnoreCase, rfReplaceAll]);
			WriteLn('sPathSkv=' + sPathSkv);

			if gbDoConvert = true then
			begin
				// STEP 2 CONVERT; The flag for conversion is true, do an conversion of LPR to SKV.
				
				DoConvert(sPathLpr, sPathSkv);
				ShowStatistics();
			end;
			
			// STEP 3 Move the out to the Splunk server for indexing and archiving.
			MoveOutput(sPathLpr, sPathSkv);
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


begin
	ProgInit();
	ProgRun();
	//ProgTest();
	ProgDone();
end. // of program ExportEvents