; from Tom Hughes' Syslog 0.19
;
; Macro:	RET
;
; Description:	Return from a subroutine
;
; Inputs:	$LR - The register containing the return address, which
;		      defaults to R14 if not specified
;		$CC - An optional condition code
;
		MACRO
$Label		RET		$LR,$CC
		LCLS		TempLR
	[ "$LR" = ""
TempLR		SETS		"lr"
	|
TempLR		SETS		"$LR"
	]
	[ {CONFIG} = 26
$Label		MOV$CC.S	pc,$TempLR
	|
$Label		MOV$CC		pc,$TempLR
	]
		MEND

;
; Macro:	ENTER
;
; Description:	Generate subroutine entry code
;
; Inputs:	$RegList - List of registers to save
;
		MACRO
$Label		ENTER		$RegList
	[ "$RegList" = ""
$Label		STR		lr,[sp,#-4]!
	|
$Label		STMFD		sp!,{$RegList,lr}
	]
		MEND

;
; Macro:	EXIT
;
; Description:	Generate subroutine exit code
;
; Inputs:	$RegList - List of registers to restore
;		$NewSub - If present, do a tail call to pass control
;		          to this routine instead of returning
;		$CC - An optional condition code
;
		MACRO
$Label		EXIT		$RegList,$NewSub,$CC
	[ "$NewSub" = ""
	  [ {CONFIG} = 26
	    [ "$RegList" = ""
$Label		LDM$CC.FD	sp!,{pc}^
	    |
$Label		LDM$CC.FD	sp!,{$RegList,pc}^
	    ]
	  |
	    [ "$RegList" = ""
$Label		LDR$CC		pc,[sp],#4
	    |
$Label		LDM$CC.FD	sp!,{$RegList,pc}
	    ]
	  ]
	|
	  [ "$RegList" = ""
$Label		LDR$CC		pc,[lr],#4
	  |
$Label		LDM$CC.FD	sp!,{$RegList,lr}
	  ]
		B$CC		$NewSub
	]
		MEND

		AREA		|syslog$$code|, PIC, CODE, READONLY

		EXPORT		syslog_logmessage
syslog_logmessage
		MOV		R12,R14
		SWI		&4C880
		RET		R12

		EXPORT		syslog_getloglevel
syslog_getloglevel
		MOV		R12,R14
		SWI		&4C881
		RET		R12

		EXPORT		syslog_flushlog
syslog_flushlog
		MOV		R12,R14
		SWI		&4C882
		RET		R12

		EXPORT		syslog_setloglevel
syslog_setloglevel
		MOV		R12,R14
		SWI		&4C883
		RET		R12

		EXPORT		syslog_logunstamped
syslog_logunstamped
		MOV		R12,R14
		SWI		&4C884
		RET		R12

		EXPORT		syslog_indent
syslog_indent
		MOV		R12,R14
		SWI		&4C885
		RET		R12

		EXPORT		syslog_unindent
syslog_unindent
		MOV		R12,R14
		SWI		&4C886
		RET		R12

		EXPORT		syslog_noindent
syslog_noindent
		MOV		R12,R14
		SWI		&4C887
		RET		R12

		EXPORT		syslog_opensessionlog
syslog_opensessionlog
		MOV		R12,R14
		SWI		&4C888
		RET		R12

		EXPORT		syslog_closesessionlog
syslog_closesessionlog
		MOV		R12,R14
		SWI		&4C889
		RET		R12

		EXPORT		syslog_logdata
syslog_logdata
		ENTER		R4
		LDR		R4,[R13,#8]
		SWI		&4C88A
		EXIT		R4

		EXPORT		syslog_readerrormessage
syslog_readerrormessage
		MOV		R12,R14
		SWI		&4C88C
		RET		R12

		EXPORT		syslog_logcomplete
syslog_logcomplete
		MOV		R12,R14
		SWI		&4C88D
		RET		R12

		EXPORT		syslog_irqmode
syslog_irqmode
		MOV		R12,R14
		SWI		&4C88E
		RET		R12

		EXPORT		xsyslog_logmessage
xsyslog_logmessage
		MOV		R12,R14
		SWI		&6C880
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_getloglevel
xsyslog_getloglevel
		MOV		R12,R14
		SWI		&6C881
		STRVC		R0,[R1]
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_flushlog
xsyslog_flushlog
		MOV		R12,R14
		SWI		&6C882
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_setloglevel
xsyslog_setloglevel
		MOV		R12,R14
		SWI		&6C883
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_logunstamped
xsyslog_logunstamped
		MOV		R12,R14
		SWI		&6C884
		MOVVC		R0,#0
		RET		R12

		EXPORT	xsyslog_indent
xsyslog_indent
		MOV		R12,R14
		SWI		&6C885
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_unindent
xsyslog_unindent
		MOV   		R12,R14
		SWI   		&6C886
		MOVVC 		R0,#0
		RET   		R12

		EXPORT		xsyslog_noindent
xsyslog_noindent
		MOV		R12,R14
		SWI		&6C887
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_opensessionlog
xsyslog_opensessionlog
		MOV   		R12,R14
		SWI   		&6C888
		STRVC 		R0,[R2]
		MOVVC 		R0,#0
		RET   		R12

		EXPORT		xsyslog_closesessionlog
xsyslog_closesessionlog
		MOV		R12,R14
		SWI		&6C889
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_logdata
xsyslog_logdata
		ENTER		R4
		LDR   		R4,[R13,#8]
		SWI   		&6C88A
		MOVVC 		R0,#0
		EXIT		R4

		EXPORT		xsyslog_readerrormessage
xsyslog_readerrormessage
		MOV		R12,R14
		SWI		&6C88C
		STRVC		R0,[R1]
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_logcomplete
xsyslog_logcomplete
		MOV		R12,R14
		SWI		&6C88D
		MOVVC		R0,#0
		RET		R12

		EXPORT		xsyslog_irqmode
xsyslog_irqmode
		MOV		R12,R14
		SWI		&6C88E
		MOVVC		R0,#0
		RET		R12

		IMPORT		vsprintf
		EXPORT		syslogf
syslogf
		MOV		R12,R13
		STMDB		R13!,{R3}
		STMDB		R13!,{R0,R1,R11,R12,R14,PC}
		SUB		R11,R12,#8
		MOV		R1,R2
		ADD 		R2,R11,#4
		STR		R2,[R13,#-4]!
		MOV		R2,R13
		LDR		R0,_syslogf_temp_adr
		BL		vsprintf
		LDR		R2,[R11,#-&10]
		LDR		R1,_syslogf_temp_adr
		LDR		R0,[R11,#-&14]
		SWI		&4C880
	[ {CONFIG} = 26
		LDMDB		R11,{R11,R13,PC}^
	|
		LDMDB		R11,{R11,R13,PC}
	]

		EXPORT		xsyslogf
xsyslogf
		MOV		R12,R13
		STMDB		R13!,{R3}
		STMDB		R13!,{R0,R1,R11,R12,R14,PC}
		SUB		R11,R12,#8
		MOV		R1,R2
		ADD 		R2,R11,#4
		STR		R2,[R13,#-4]!
		MOV		R2,R13
		LDR		R0,_syslogf_temp_adr
		BL		vsprintf
		LDR		R2,[R11,#-&10]
		LDR		R1,_syslogf_temp_adr
		LDR		R0,[R11,#-&14]
		SWI		&6C880
		MOVVC		R0,#0
	[ {CONFIG} = 26
		LDMDB		R11,{R11,R13,PC}^
	|
		LDMDB		R11,{R11,R13,PC}
	]

_syslogf_temp_adr
		&		_syslogf_temp

		AREA		|syslog$$zinit|, NOINIT

_syslogf_temp
		%		1536

		END
