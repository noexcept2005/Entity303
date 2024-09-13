/*		Entity303.dll      
 *   Author: noexcept(Wormwaker)
 *   CopyRight (C) 2050
 *    %%% ALL RIGHTS RESERVED %%%
 *   Tip: Must run by exec.exe
 */

#include "dll.h"

#include <strings.h>
#include <windows.h>
#include <winable.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <tlhelp32.h>
#include <shlp.h>  
#include <sys/time.h>
#include <time.h>
#include <tchar.h>

#define version "1.1.2"
#define VERSION_DATE 20200929


#define NUMPRINT(expr) {\
		LPSTR __str;\
		sprintf(__str,"%d",expr);\
		MessageBox(NULL,(LPCSTR)__str,#expr,MB_ICONEXCLAMATION|MB_OK);\
						}
#define STRPRINT(str) {\
		MessageBox(NULL,(LPCSTR)str,#str,MB_ICONEXCLAMATION|MB_OK);\
						}

#ifndef KEY_DOWN
#define KEY_DOWN(VK_NONAME) ((GetAsyncKeyState(VK_NONAME)& 0x8000 ? 1:0))
#endif

#define MOUSE_LEFT_DOWN KEY_DOWN(MOUSE_MOVED)
#define LEFT_CLICK MOUSE_LEFT_DOWN
	#define CLICK LEFT_CLICK

#define waitfor(cond) while(!cond)

//C was not allowed in stdcjz.h :(

DLLIMPORT VOID SetColor(UINT uFore,UINT uBack) 
{
	HANDLE handle=GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleTextAttribute(handle,uFore+uBack*0x10);
	//CloseHandle(handle); 
}

//开线程 
HANDLE _CreateThread(LPTHREAD_START_ROUTINE func_name)
{ //###警告！！函数格式必须为 DWORD FUNC(LPVOID XXX) ###
	return CreateThread(NULL,0,func_name,NULL,0,NULL);
}


DLLIMPORT void HelloWorld()
{
	MessageBox(0,"Hello World!\n","Entity303",MB_ICONINFORMATION);
}
DLLIMPORT void About() 
{
	printf("\n[Entity303/INFO] Entity303.DLL About\n\tmade by noexcept");
	Sleep(10);
	printf("\n\tStart Date: 20200831");
	printf("\n\tCURRENT VERSION:%s\n",version);
	printf("\n\tCURRENT VERSION DATE:%d\n",VERSION_DATE);
}
LONG GetMousePosX()
{
	POINT pt;
	GetCursorPos(&pt);
	return pt.x;
}
LONG GetMousePosY()
{
	POINT pt;
	GetCursorPos(&pt);
	return pt.y;
}
DLLIMPORT void CloseUAC(VOID)
{//须管理员权限 
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		Sleep(500);
		return;
	}
	WinExec("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"ConsentPromptBehaviorAdmin\" /t REG_DWORD /d 0 /F",SW_HIDE);
	WinExec("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"EnableLUA\" /t REG_DWORD /d 0 /F",SW_HIDE);
	WinExec("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v \"PromptOnSecureDesktop\" /t REG_DWORD /d 0 /F",SW_HIDE);
}//关机后应用

VOID Execute(LPCSTR lpFile,LPCSTR lpArguments) 
{//UNSOLVED ERROR(if I add 'iCmdShow' with a default argument): [Error] expected ';', ',' or ')' before '=' token
	ShellExecute(0,"open",lpFile,lpArguments,"",SW_HIDE);
	return;
}

BOOL prv_debug = false;

DLLIMPORT VOID GetDebugPrivilege()
{	//调 试 模 式 
	HANDLE hToken;
    BOOL fOk=FALSE;
    SetColor(14,0);
    printf("\n[Entity303/INFO] Getting debug privilege...");
    Sleep(100);
    /*if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken)){ //Get Token
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount=1;
        if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid))//Get Luid
        {
//        	SetLastError();
			CloseHandle(hToken);
        	SetColor(12,0);
        	printf("\n[Entity303/ERROR] Cannot Lookup the privilege value!");
        	return;
		}
        tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;//这一句很关键，修改其属性为SE_PRIVILEGE_ENABLED
        if(!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL))//Adjust Token
        {
//        	cout<<"Can't adjust privilege value"<<endl;
//			SetLastError();
			CloseHandle(hToken);
			SetColor(12,0);
        	printf("\n[Entity303/ERROR] Cannot Adjust the token privilege!");
			return;
		}
        fOk=(GetLastError()==ERROR_SUCCESS);
        CloseHandle(hToken);
        hToken=NULL;
    }else{
    	SetColor(12,0);
        printf("\n[Entity303/ERROR] Cannot open process token!");
	}*/
		typedef BOOL(WINAPI *RtlAdjustPrivilege) (ULONG, BOOL, BOOL, PBOOLEAN); 
		
		RtlAdjustPrivilege AdjustPrivilege; 
// 加载 ntdll 以及相关 API 
		HANDLE ntdll = LoadLibrary(TEXT("ntdll.dll")); 
		AdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress((HINSTANCE)ntdll, "RtlAdjustPrivilege"); 
//		SetCriticalProcess = (RtlSetProcessIsCritical)GetProcAddress((HINSTANCE)ntdll, "RtlSetProcessIsCritical"); 
		BOOLEAN b; 
// 进程提升至 Debug 权限，需要 UAC 管理员许可 
		AdjustPrivilege(20UL, TRUE, FALSE, &b); 
		
		fOk=true;
	if(fOk)
	{
		SetColor(10,0);
		printf("\n[Entity303/INFO]Succeeded in getting the privilege!");
		Sleep(200);
		SetColor(14,0);
		printf("\n[Entity303/INFO](***RUNNING ON DEBUG MODE!***)");
		prv_debug = true;
	}
	Sleep(500);
    return;
}

DLLIMPORT VOID DEBUGMODE()
{
	GetDebugPrivilege();
}

DLLIMPORT VOID GetShutdownPrivilege()
{	//调 试 模 式 
	HANDLE hToken;
    BOOL fOk=FALSE;
    SetColor(14,0);
    printf("\n[Entity303/INFO]Getting SHUTDOWN privilege...");
    Sleep(100);
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken)){ //Get Token
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount=1;
        if(!LookupPrivilegeValue(NULL,SE_SHUTDOWN_NAME,&tp.Privileges[0].Luid))//Get Luid
        {
//        	SetLastError();
			CloseHandle(hToken);
        	SetColor(12,0);
        	printf("\n[Entity303/ERROR] Cannot Lookup the privilege value!");
        	return;
		}
        tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;//这一句很关键，修改其属性为SE_PRIVILEGE_ENABLED
        if(!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL))//Adjust Token
        {
//        	cout<<"Can't adjust privilege value"<<endl;
//			SetLastError();
			CloseHandle(hToken);
			SetColor(12,0);
        	printf("\n[Entity303/ERROR] Cannot Adjust the token privilege!");
			return;
		}
        fOk=(GetLastError()==ERROR_SUCCESS);
        CloseHandle(hToken);
        hToken=NULL;
    }else{
    	SetColor(12,0);
        printf("\n[Entity303/ERROR] Cannot open process token!");
	}
	if(fOk)
	{
		SetColor(10,0);
		printf("\n[Entity303/INFO]Succeeded in getting the privilege!");
		/*Sleep(200);
		SetColor(14,0);
		printf("\n[Entity303/INFO](***RUNNING ON SHUTDOWN PRIVILEGE MODE!***)");
		prv_debug = true;*/
	}
	Sleep(500);
    return;
}
DLLIMPORT VOID SHUTDOWNMODE()
{
	GetShutdownPrivilege();
}
DLLIMPORT VOID SHUTDOWNPRIVILEGE()
{
	GetShutdownPrivilege();
}
DLLIMPORT VOID SHUTDOWNPRV()
{
	GetShutdownPrivilege();
}

DLLIMPORT VOID GetSecurityPrivilege()
{	//安全权限 
	HANDLE hToken;
    BOOL fOk=FALSE;
    SetColor(14,0);
    printf("\n[Entity303/INFO] Getting Security privilege...");
    Sleep(100);
    if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken)){ //Get Token
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount=1;
        if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid))//Get Luid
        {
//        	SetLastError();
			CloseHandle(hToken);
        	SetColor(12,0);
        	printf("\n[Entity303/ERROR] Cannot Lookup the privilege value!");
        	return;
		}
        tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;//这一句很关键，修改其属性为SE_PRIVILEGE_ENABLED
        if(!AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL))//Adjust Token
        {
//        	cout<<"Can't adjust privilege value"<<endl;
//			SetLastError();
			CloseHandle(hToken);
			SetColor(12,0);
        	printf("\n[Entity303/ERROR] Cannot Adjust the token privilege!");
			return;
		}
        fOk=(GetLastError()==ERROR_SUCCESS);
        CloseHandle(hToken);
        hToken=NULL;
    }else{
    	SetColor(12,0);
        printf("\n[Entity303/ERROR] Cannot open process token!");
	}
	if(fOk)
	{
		SetColor(10,0);
		printf("\n[Entity303/INFO]Succeeded in getting the privilege!");
		Sleep(200);
		SetColor(14,0);
		printf("\n[Entity303/INFO](***RUNNING WITH SECURITY PRIVILEGE!***)");
		prv_debug = true;
	}
	Sleep(500);
    return;
}
DLLIMPORT VOID SECURITYPRV()
{
	GetSecurityPrivilege();
}
DLLIMPORT VOID SECURITYPRIVILEGE()
{
	GetSecurityPrivilege();
}
//\
/*
DLLIMPORT VOID SP()
{
	GetSecurityPrivilege();
}
//*/

VOID _DisabledTaskmgr(DWORD dwForbid)
{
	HKEY hkey;
	DWORD v = dwForbid;
	RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
	RegSetValueEx(hkey, "DisableTaskMgr", NULL, REG_DWORD, (LPBYTE)&v, sizeof(DWORD));
	RegCloseKey(hkey);
}
VOID _DisabledRegedit(DWORD dwForbid)
{//注册表修改实现禁用注册表编辑器 :须管理员权限 
	HKEY hkey;
	DWORD v = dwForbid;
	RegCreateKey(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", &hkey);
	RegSetValueEx(hkey, "DisableRegistryTools", NULL, REG_DWORD, (LPBYTE)&v, sizeof(DWORD));
	RegCloseKey(hkey);
}
DLLIMPORT VOID DisabledTaskmgr()
{
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		Sleep(500);
		return;
	}
	SetColor(3,0);
	printf("\n[Entity303/INFO]Disabling the Taskmgr..");
	Sleep(20);
	_DisabledTaskmgr(1);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Completed!");
}
DLLIMPORT VOID EnabledTaskmgr()
{
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		Sleep(500);
		return;
	}
	SetColor(3,0);
	printf("\n[Entity303/INFO]Enabling the Taskmgr..");
	Sleep(20);
	_DisabledTaskmgr(0);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Completed!");
}
DLLIMPORT VOID DisabledRegedit()
{
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		Sleep(500);
		return;
	}
	SetColor(3,0);
	printf("\n[Entity303/INFO]Disabling the Regedit..");
	Sleep(20);
	_DisabledRegedit(1);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Completed!");
}
DLLIMPORT VOID EnabledRegedit()
{
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		Sleep(500);
		return;
	}
	SetColor(3,0);
	printf("\n[Entity303/INFO]Enabling the Regedit..");
	Sleep(20);
	_DisabledRegedit(0);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Completed!");
}
DLLIMPORT void CloseMonitor(void)
{
	PostMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
}
DLLIMPORT void BlackScreen(void)
{
	SetColor(8,0);
	printf("\n[Entity303/INFO]Closing monitor..");
	Sleep(150);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Press any key or click anywhere to open monitor.");
	Sleep(350);
	CloseMonitor();
}
VOID _SystemSleep(WINBOOL bSuspend,WINBOOL bForce)
{                        //TRUE睡眠，FALSE休眠 
	HANDLE token = NULL;
	TOKEN_PRIVILEGES tp = { 0 };
	tp.PrivilegeCount = 1;
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tp.Privileges[0].Luid);
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token);
	AdjustTokenPrivileges(token, FALSE, &tp, sizeof tp, NULL, NULL);
	CloseHandle(token);
	
	SetSystemPowerState(bSuspend, bForce); // 第一个参数TRUE睡眠，FALSE休眠
    return;
}//from https://www.kechuang.org/t/82297
DLLIMPORT VOID SystemSleep(DWORD dwSuspend)//1睡眠 0休眠 
{
	SetColor(8,0);
	printf("\n[Entity303/INFO]dwSuspend=%d",dwSuspend);
	Sleep(50);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Setting system power state..");
	Sleep(200);
	_SystemSleep((WINBOOL)dwSuspend,FALSE);
	SetColor(15,0);
	printf("\n[Entity303/INFO]Completed.");
}
DLLIMPORT VOID BlackScreenPlus(VOID)
{
	SetColor(14,0);
	printf("\n[Entity303/INFO]Press F12 or Alt+F4 to escape it.");
	Sleep(400);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Running the calc..");
	Sleep(100);
	Execute("calc.exe",NULL);
	Sleep(200);
	SetColor(15,0);
	printf("\n[Entity303/INFO]FullScreening it..");
	Sleep(100);
	ShowWindow(GetForegroundWindow()/*FindWindow("NULL","计算器")*/,SW_MAXIMIZE);
	_Click();
	SetColor(7,0);
	printf("\n[Entity303/INFO]Blacking screen...");
	CloseMonitor();
	SetColor(15,0);
	printf("\n[Entity303/INFO]Completed!Waiting for escaping(F12||Alt+F4)...\n");
	Sleep(50);
	ShowWindow(GetConsoleWindow(),SW_HIDE);
	int x,y;
	x=GetMousePosX();
	y=GetMousePosY();
	while(_HaveProcessByName("calculator.exe"))
	{
		if(KEY_DOWN(VK_F12))
			break;
		if(kbhit() || CLICK)
		{
			CloseMonitor();
		}else if(GetMousePosX() != x || GetMousePosY() != y)
		{	
			CloseMonitor();
			x=GetMousePosX();
			y=GetMousePosY();
		}
		Sleep(20);
	}
	system("taskkill /im calculator.exe /f");
	Sleep(800);
	ShowWindow(GetConsoleWindow(),SW_SHOW);
	Sleep(300);
	SetColor(15,0);
	printf("\n[Entity303/INFO]Escaped.");
}
DLLIMPORT VOID BSP()
{
	BlackScreenPlus();
}


//是否Win7 
BOOL IsWin7System()  
{  
    OSVERSIONINFOEX osvi;  
    BOOL bOsVersionInfoEx;  
      
    ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));  
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);  
    bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO*) &osvi);  
      
    // win7的系统版本为NT6.1  
    if ( VER_PLATFORM_WIN32_NT == osvi.dwPlatformId &&    
        osvi.dwMajorVersion == 6 &&   
        osvi.dwMinorVersion == 1 )  
    {  
        return TRUE;      
    }  
    else  
    {  
        return FALSE;  
    }  
}//from https://blog.csdn.net/maigao1/article/details/79522825

// 判断是否是Win10系统
BOOL IsWin10System()
{
	//string与CString转换
	//string sPath = (LPCSTR)(CStringA)(strPath);
//	std::string vname;
	// 先判断是否为win8.1或win10
	typedef void(__stdcall*NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary(_T("ntdll.dll"));
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);
	if (dwMajor == 10 && dwMinor == 0)
	{
		return TRUE;
	}
	return FALSE;
}//from https://blog.csdn.net/m0_37251750/article/details/84324169

typedef enum _HARDERROR_RESPONSE_OPTION { 
OptionAbortRetryIgnore, 
OptionOk, 
OptionOkCancel, 
OptionRetryCancel, 
OptionYesNo, 
OptionYesNoCancel, 
OptionShutdownSystem, 
OptionOkNoWait, 
OptionCancelTryContinue 
}HARDERROR_RESPONSE_OPTION;

typedef LONG (WINAPI *type_ZwRaiseHardError)
	 (LONG ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, HARDERROR_RESPONSE_OPTION ValidResponseOptions, PULONG Response); 
	 
typedef struct _UNICODE_STRING 
	{ 
	USHORT Length; 
	USHORT MaximumLength; 
	PWCH Buffer; 
	}UNICODE_STRING;


BOOL SetPrivilege(LPCSTR lpPrivilegeName, WINBOOL fEnable) 
{ 							//SE_XXX_NAME
HANDLE hToken; 
TOKEN_PRIVILEGES NewState; 
LUID luidPrivilegeLUID; 

if(!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) 
{ 
/*If opening token failed...*/ 
return FALSE; 
} 

if(fEnable == FALSE) /*We disable all the privileges... */ 
{ 
if(!AdjustTokenPrivileges(hToken, TRUE, NULL, NULL, NULL, NULL)) 
{ 
return FALSE; 
} 
else return TRUE; 
} 
/*Look up the LUID value of the privilege... */ 
LookupPrivilegeValue(NULL, lpPrivilegeName, &luidPrivilegeLUID); 
NewState.PrivilegeCount = 1; 
NewState.Privileges[0].Luid = luidPrivilegeLUID; 
NewState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
/*Improve this process's privilege, so we can shut down the system next. */ 
if(!AdjustTokenPrivileges(hToken, FALSE, &NewState, NULL, NULL, NULL)) 
{ 
return FALSE; 
} 
/*We should not only check if the improving was successed... */ 
if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) 
{ 
return FALSE; 
} 
return TRUE; 
}
//from https://www.cnblogs.com/p-a/articles/C-LANGUAGE-BSOD.html

DLLIMPORT VOID _BlueScreen(VOID)
{//警告：须管理员权限！！
 //程序格式参考 https://blog.csdn.net/cjz2005/article/details/104513305/
 	
 	/*if(IsWin7System())
 	{*/ 
 		HWINSTA hWinSta; 
	hWinSta = CreateWindowStation("_entity303_BlueScreen", NULL, 55, NULL); 
	SetHandleInformation(hWinSta, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE); 
	CloseWindowStation(hWinSta); 	//Windows站点退出 
//	}
	/*else if(IsWin10System())
	{*/ 
		/*
		UNICODE_STRING str = {8, 10, L"BlueScreen"}; 
		ULONG x, args[] = {0x12345678, 0x87654321, (ULONG)&str}; 
	HMODULE hDll = GetModuleHandle(TEXT("ntdll.dll")); 
	type_ZwRaiseHardError ZwRaiseHardError = (type_ZwRaiseHardError)GetProcAddress(hDll, "ZwRaiseHardError");
	
	bool bSuccess = SetPrivilege(SE_SHUTDOWN_NAME, TRUE); 
	if(bSuccess) 		//触发严重错误 
		ZwRaiseHardError(0xC000021A, 3, 4, args, OptionShutdownSystem, &x); 
	SetPrivilege(NULL, FALSE);*/
		typedef NTSTATUS(WINAPI *RtlSetProcessIsCritical) (BOOLEAN, PBOOLEAN, BOOLEAN); 
		typedef BOOL(WINAPI *RtlAdjustPrivilege) (ULONG, BOOL, BOOL, PBOOLEAN); 
		
		RtlAdjustPrivilege AdjustPrivilege; 
		RtlSetProcessIsCritical SetCriticalProcess; 
// 加载 ntdll 以及相关 API 
		HANDLE ntdll = LoadLibrary(TEXT("ntdll.dll")); 
		AdjustPrivilege = (RtlAdjustPrivilege)GetProcAddress((HINSTANCE)ntdll, "RtlAdjustPrivilege"); 
		SetCriticalProcess = (RtlSetProcessIsCritical)GetProcAddress((HINSTANCE)ntdll, "RtlSetProcessIsCritical"); 
		BOOLEAN b; 
		
		if(AdjustPrivilege == NULL || SetCriticalProcess == NULL)
		{
			goto _b2;
		 } 
// 进程提升至 Debug 权限，需要 UAC 管理员许可 
		AdjustPrivilege(20UL, TRUE, FALSE, &b); 
// 设置为 Critical Process 
		SetCriticalProcess(TRUE, NULL, FALSE); 
// 退出，触发 CRITICAL_PROCESS_DIED 蓝屏
//	}else{						//直接杀掉关键进程 
_b2:
		system("taskkill /im wininit.exe /f");
 		system("taskkill /im winlogon.exe /f"); 
//	}
	return;
}//from https://www.cnblogs.com/p-a/articles/C-LANGUAGE-BSOD.html

DLLIMPORT VOID BlueScreen()
{
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		Sleep(500);
		return;
	}
	/*if(!prv_debug)
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no DEBUG privilege!Input 'DEBUGMODE' to get it.");
		Sleep(500);
		return;
	}*/
	SetColor(14,0);
	printf("\n[Entity303/WARN]DO YOU REALLY WANT TO MAKE A BLUESCREEN? [Y/N]");
	int ch;
_inp:
	ch=getch();
	if(ch == 'n' || ch == 'N')
	{
		SetColor(8,0);
		printf("\n[Entity303/INFO]Cancelled this operation.");
	}else if(ch == 'y' || ch == 'Y')
	{
		SetColor(11,0);
		printf("\n[Entity303/INFO]You've made sure,and I won't hesitate :|");
		Sleep(800);
		GetShutdownPrivilege();
		Sleep(200);
		SetColor(3,0);
		printf("\n[Entity303/INFO]Making BLUESCREEN.. ");
		Sleep(300);
		printf(":D");
		Sleep(800);
		SetColor(10,0);
		printf("\n[Entity303/INFO]Completed!Please wait a minute..It would be blue soon. :D");
		_BlueScreen();
		Sleep(20000);
		SetColor(14,0);
		printf("\n[Entity303/INFO]READY TO BE BLUE..");
		MessageBox(NULL,"READY TO BE BLUE...","Entity303::BlueScreen",MB_ICONEXCLAMATION|MB_OK|MB_TOPMOST|MB_SYSTEMMODAL);
		Sleep(2000);
	}else{
		goto _inp;
	}
}

DLLIMPORT BOOL DeleteDrive(LPCSTR SThide)
//删除盘符                                    //填 C:  D:之类 
{
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		Sleep(500);
		return;
	}
	Sleep(100);
	SetColor(3,0);
	printf("\n[Entity303/INFO]Deleting(Modify it to \"\")..");
	if (!DefineDosDevice(DDD_RAW_TARGET_PATH, (LPCSTR)SThide, ""))
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting it :(");
		Sleep(250);
	}
	else{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting it.");
		Sleep(200);
		SetColor(3,0);
		printf("\n[Entity303/INFO]It's dangerous,you know.");
		Sleep(600);
	}
}
DLLIMPORT VOID ModifyDrive(VOID)
{//修改盘符 
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		Sleep(500);
		return;
	}
	char SThide[32];
	char newLook[128];
	SetColor(2,0);
	printf("\n[Entity303/INFO]Input pect Drive(Such as C: , D:): ");
	SetColor(8,0);
	scanf("%s",&SThide);
	SetColor(10,0);
	printf("\n[Entity303/INFO]Input new Drive name: ");
	SetColor(8,0);
	scanf("%s",&newLook);
	Sleep(100);
	SetColor(3,0);
	printf("\n[Entity303/INFO]Modifing..");
	if (!DefineDosDevice(DDD_RAW_TARGET_PATH, (LPCSTR)SThide, (LPCSTR)newLook))
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in modifing it :(");
		Sleep(250);
	}
	else{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in modifing it.");
		Sleep(200);
		SetColor(3,0);
		printf("\n[Entity303/INFO]It's dangerous,you know.");
		Sleep(600);
	}
}


/*
DLLIMPORT void RegHideHidden()
{ //资源管理器显不显示隐藏文件 
	HKEY hkey;
//	DWORD v = (bShow == true ? 1 : 0);
	DWORD v = 0;
	/*RegCreateKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL", &hkey);
	RegSetValueEx(hkey, "CheckedValue", NULL, REG_DWORD, (LPBYTE)&v, sizeof(DWORD));
	RegCloseKey(hkey);*//*
	if(v == 0)
		WinExec("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\" /v \"CheckedValue\" /t REG_DWORD /d 0 /F",SW_HIDE);
	else
		WinExec("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\" /v \"CheckedValue\" /t REG_DWORD /d 1 /F",SW_HIDE);
}
DLLIMPORT void RegShowHidden()
{ //资源管理器显不显示隐藏文件 
	HKEY hkey;
//	DWORD v = (bShow == true ? 1 : 0);
	DWORD v = 1;
	/*RegCreateKey(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL", &hkey);
	RegSetValueEx(hkey, "CheckedValue", NULL, REG_DWORD, (LPBYTE)&v, sizeof(DWORD));
	RegCloseKey(hkey);*//*
	if(v == 0)
		WinExec("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\" /v \"CheckedValue\" /t REG_DWORD /d 0 /F",SW_HIDE);
	else
		WinExec("reg add \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced\\Folder\\Hidden\\SHOWALL\" /v \"CheckedValue\" /t REG_DWORD /d 1 /F",SW_HIDE);
}*/
DLLIMPORT void ShutdownNow()
{
	system("shutdown -p");
}
DLLIMPORT void Logoff()
{
	system("logoff");
}
DLLIMPORT void ShowTaskbar()
{
	ShowWindow (FindWindow("Shell_TrayWnd", NULL), SW_SHOW); // 显示任务栏
	SetColor(7,0);
	printf("\n[Entity303/INFO]'ve showed the taskbar.");
}
DLLIMPORT void HideTaskbar()
{
	ShowWindow (FindWindow("Shell_TrayWnd", NULL), SW_HIDE); // 显示任务栏
	SetColor(7,0);
	printf("\n[Entity303/INFO]'ve hidden the taskbar.");
}

#define DISABLE_QUICK_EDIT_MODE 0x01
#define DISABLE_INSERT_MODE 0x02
#define DISABLE_MOUSE_INPUT 0x03 
#define DISABLE_ALL (DISABLE_QUICK_EDIT_MODE | DISABLE_INSERT_MODE | DISABLE_MOUSE_INPUT)

VOID CloseConsoleMode(UINT uTag)
{
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);  
        DWORD mode;  
        GetConsoleMode(hStdin, &mode);  
        if(uTag & DISABLE_QUICK_EDIT_MODE)
        	mode &= ~ENABLE_QUICK_EDIT_MODE;  //移除快速编辑模式
    	if(uTag & DISABLE_INSERT_MODE)
        	mode &= ~ENABLE_INSERT_MODE;      //移除插入模式
        if(uTag & DISABLE_MOUSE_INPUT)
        	mode &= ~ENABLE_MOUSE_INPUT;
        SetConsoleMode(hStdin, mode);  
    return;
}
VOID OpenConsoleMode(UINT uTag)
{
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);  
        DWORD mode;  
        GetConsoleMode(hStdin, &mode);  
        if(uTag & DISABLE_QUICK_EDIT_MODE)
        	mode &= ENABLE_QUICK_EDIT_MODE;  //快速编辑模式
    	if(uTag & DISABLE_INSERT_MODE)
        	mode &= ENABLE_INSERT_MODE;      //插入模式
        if(uTag & DISABLE_MOUSE_INPUT)
        	mode &= ENABLE_MOUSE_INPUT;
        SetConsoleMode(hStdin, mode);  
    return;
}
DLLIMPORT VOID _CloseConsoleQuickEditMode(VOID)
{
	CloseConsoleMode(DISABLE_QUICK_EDIT_MODE);
}
DLLIMPORT VOID CloseConsoleQuickEditMode(VOID)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]QUICK EDIT MODE: ");
	SetColor(12,0);
	printf("OFF");
	_CloseConsoleQuickEditMode();
}
DLLIMPORT VOID CCQEM(VOID)
{
	CloseConsoleQuickEditMode(); 
} 
DLLIMPORT VOID _CloseConsoleInsertMode(VOID)
{
	CloseConsoleMode(DISABLE_INSERT_MODE);
}
DLLIMPORT VOID CloseConsoleInsertMode(VOID)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]INSERT MODE: ");
	SetColor(12,0);
	printf("OFF");
	_CloseConsoleInsertMode();
}
DLLIMPORT VOID CCIM(VOID)
{
	CloseConsoleInsertMode();
}
DLLIMPORT VOID _CloseConsoleMouseInput(VOID)
{
	CloseConsoleMode(DISABLE_MOUSE_INPUT);
}
DLLIMPORT VOID CloseConsoleMouseInput(VOID)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]CONSOLE MOUSE INPUT: ");
	SetColor(12,0);
	printf("OFF");
	_CloseConsoleMouseInput();
}
DLLIMPORT VOID CCMI(VOID)
{
	CloseConsoleMouseInput();
}


DLLIMPORT VOID _OpenConsoleQuickEditMode(VOID)
{
	OpenConsoleMode(DISABLE_QUICK_EDIT_MODE);
}
DLLIMPORT VOID OpenConsoleQuickEditMode(VOID)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]QUICK EDIT MODE: ");
	SetColor(10,0);
	printf("ON");
	_CloseConsoleQuickEditMode();
}
DLLIMPORT VOID OCQEM(VOID)
{
	OpenConsoleQuickEditMode(); 
} 
DLLIMPORT VOID _OpenConsoleInsertMode(VOID)
{
	OpenConsoleMode(DISABLE_INSERT_MODE);
}
DLLIMPORT VOID OpenConsoleInsertMode(VOID)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]INSERT MODE: ");
	SetColor(10,0);
	printf("ON");
	_OpenConsoleInsertMode();
}
DLLIMPORT VOID OCIM(VOID)
{
	OpenConsoleInsertMode();
}
DLLIMPORT VOID _OpenConsoleMouseInput(VOID)
{
	OpenConsoleMode(DISABLE_MOUSE_INPUT);
}
DLLIMPORT VOID OpenConsoleMouseInput(VOID)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]CONSOLE MOUSE INPUT: ");
	SetColor(10,0);
	printf("ON");
	_OpenConsoleMouseInput();
}
DLLIMPORT VOID OCMI(VOID)
{
	OpenConsoleMouseInput();
}
DLLIMPORT VOID _HideConsoleCursor() 
{
	CONSOLE_CURSOR_INFO cursor_info = {1, 0};
	SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursor_info);
}
DLLIMPORT VOID HideConsoleCursor()
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]CONSOLE CURSOR: ");
	SetColor(12,0);
	printf("HIDDEN");
	_HideConsoleCursor();
}
DLLIMPORT VOID _ShowConsoleCursor() 
{
	CONSOLE_CURSOR_INFO cursor_info = {1, 1};
	SetConsoleCursorInfo(GetStdHandle(STD_OUTPUT_HANDLE), &cursor_info);
}
DLLIMPORT VOID ShowConsoleCursor()
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]CONSOLE CURSOR: ");
	SetColor(10,0);
	printf("SHOWN");
	_ShowConsoleCursor();
}


VOID FloatWindow(HWND hwnd) //使窗口置顶 
{
	SetWindowPos(hwnd,(true ? HWND_TOPMOST : HWND_TOP),0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_DRAWFRAME);
	//SetForegroundWindow(hwnd);
}
VOID UnfloatWindow(HWND hwnd)
{
	SetWindowPos(hwnd,HWND_NOTOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_DRAWFRAME);
}

bool _kfc_running;

DWORD _KeepFloatingConsole(LPVOID anything)
{
	_kfc_running = true;
	SetColor(3,0);
	printf("\n[Entity303/INFO] (THREAD) Started keeping floating console.\n");
	SetColor(14,0);
	while(_kfc_running)
	{
		Sleep(10);
		FloatWindow(GetConsoleWindow());
	}
	Sleep(15);
	SetColor(3,0);
	printf("\n[Entity303/INFO] (THREAD) Closed.\n");
	SetColor(15,0);
}
DLLIMPORT _StartFloatingConsole()
{
	_CreateThread(_KeepFloatingConsole);
}
DLLIMPORT StartFloatingConsole()
{
	SetColor(15,0);
	printf("\n[Entity303/INFO]Starting Console-Floating THREAD..");
	Sleep(20);
	_StartFloatingConsole();
}
DLLIMPORT _FreeFloatingConsole()
{
	_kfc_running = false;
	UnfloatWindow(GetConsoleWindow());
}
DLLIMPORT FreeFloatingConsole()
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]Close the Console-Floating THREAD..");
	_FreeFloatingConsole();
}
/*
COLORREF GetCursorPointColor()
//获取鼠标处颜色					注意：若hdc不为空，则得到的是某窗口鼠标处的颜色！ 
{
	POINT pt;
	GetCursorPos(&pt);
	return GetPixel(NULL,pt.x,pt.y);
	//警告：使用GetPixel必须链接libgdi32!!! 
}
#define GetCursorColor GetCursorPointColor


VOID SeparateRGB(COLORREF color,LPINT R,LPINT G,LPINT B)
{	//分离RGB颜色 
	R = GetRValue(color);
	G = GetGValue(color);
	B = GetBValue(color);
	return;
}*/
VOID _MousePos(/*bool color_indicate*/)
{
	_HideConsoleCursor();
	SetColor(8,0);
	printf("\n[Entity303/INFO]Disabling Console Quick Edit Mode..");
	CloseConsoleQuickEditMode();
	
	StartFloatingConsole();
	
	SetColor(15,0);
	printf("\n[Entity303/INFO]Starting Mouse position indicating..");
	Sleep(100);
	SetColor(7,0);
	printf("\n[Entity303/INFO]MOUSE POSITION INDICATING"
			"\n\t\tMove mouse to refresh the coordination."
			"\n\t\tSpace: Turn ON/OFF the Position Recording Mode."
			"\n\t\t    Click: Record current position"
			"\n\t\tEsc: Exit Indicating");
	Sleep(200);
	SetColor(15,0);
	printf("\n[Entity303/INFO]Begin to Show the pos.");
	Sleep(20);
	bool b_prm = false;
	bool b_pressed = false;
	long long cnt=0;
	SetColor(14,0);
	printf("\n[Entity303/INFO]MOUSE POS:X= %d,Y= %d            ",GetMousePosX(),GetMousePosY());
	
	/*if(color_indicate)
	{
		LPINT r,g,b;
		COLORREF clr = GetCursorColor();
		SeparateRGB(clr,r,g,b);
		SetColor(7,0);
		printf(" Color R:%d G:%d B:%d",r,g,b);
	}else{
		printf("                    ");
	}*/
	while(1)
	{
		if(kbhit())
		{
			int ch = getch();
			switch(ch)
			{
				case ' ':
					b_pressed = true;
					b_prm = !b_prm;
					if(b_prm)
					{
						SetColor(7,0);
						printf("\n[Entity303/INFO]Position Recording Mode: ");
						SetColor(10,0);
						printf("ON");
					}else{
						SetColor(7,0);
						printf("\n[Entity303/INFO]Position Recording Mode: ");
						SetColor(12,0);
						printf("OFF");
					}
					break;
				case 27:
					b_pressed = true;
					SetColor(7,0);
					printf("\n[Entity303/INFO]Exitting..");
					
					_ShowConsoleCursor();
					FreeFloatingConsole();
					
					Sleep(150);
					return;
					break;
				default:
					b_pressed = false;
					break;
			}
			Sleep(90);
		}else if(b_prm && LEFT_CLICK)
		{
			++cnt;
			b_pressed = true;
			SetColor(8,0);
			printf("\r[Entity303/INFO]Record %d:X= %d,Y= %d           ",cnt,GetMousePosX(),GetMousePosY());
			/*if(color_indicate)
			{
				LPINT r,g,b;
				COLORREF clr = GetCursorColor();
				SeparateRGB(clr,r,g,b);
				SetColor(7,0);
				printf(" Color R:%d G:%d B:%d",r,g,b);
			}else{
				printf("                    ");
			}*/
			Sleep(50);
		}
		if(b_pressed)
		{
			SetColor(14,0);
			printf("\n[Entity303/INFO]MOUSE POS:X= %d,Y= %d           ",GetMousePosX(),GetMousePosY());
			/*if(color_indicate)
			{
				LPINT r,g,b;
				COLORREF clr = GetCursorColor();
				SeparateRGB(clr,r,g,b);
				SetColor(7,0);
				printf(" Color R:%d G:%d B:%d",r,g,b);
			}else{
				printf("                    ");
			}*/
			b_pressed = false;
			Sleep(60);
		}else{
			printf("\r[Entity303/INFO]MOUSE POS:X= %d,Y= %d           ",GetMousePosX(),GetMousePosY());
			/*if(color_indicate)
			{
				LPINT r,g,b;
				COLORREF clr = GetCursorColor();
				SeparateRGB(clr,r,g,b);
				SetColor(7,0);
				printf(" Color R:%d G:%d B:%d",r,g,b);
			}else{
				printf("                    ");
			}*/
			Sleep(15);
		}
	}
}
DLLIMPORT VOID MousePos()
{
	_MousePos();
}/*
DLLIMPORT VOID CursorColor()
{
	_MousePos(true);
}*/
char * strass(char str[65535])
{	//char[] -> char*
	char* tmp;
	int i;
	for(i=0;i<strlen(str);i++)
	{
		tmp[i] = str[i];
	}
	return tmp;
}
LPCSTR MergePath(LPCSTR dir,LPCSTR fname)
{
	LPSTR str;
	sprintf(str,"%s\\%s",dir,fname);
	return (LPCSTR)str;
}
LPCSTR GetDesktopPath() 
{
	LPSTR str;
	//setlocale(LC_ALL,"chs");
	char path[MAX_PATH];
	SHGetSpecialFolderPath(0,path,CSIDL_DESKTOPDIRECTORY,0);
	str = strass(path);
	return (LPCSTR)str;
}

int GetYear(void){
	time_t now = time(0);
	struct tm *ltm = localtime(&now);
	return (ltm->tm_year + 1900);
} 
int GetMonth(void){
	time_t now = time(0);
	struct tm *ltm = localtime(&now);
	return (ltm->tm_mon + 1);
}
int GetDayInYear(void){
	time_t now = time(0);
	struct tm *ltm = localtime(&now);
	return (ltm->tm_yday);
}
int GetDay(void){
	time_t now = time(0);
	struct tm *ltm = localtime(&now);
	return (ltm->tm_mday);
}

VOID Download(LPCSTR lpUrl, LPCSTR lpWholePathName)
{//下载文件				     地址            目标位置 
//    HRESULT res = URLDownloadToFile(NULL, lpUrl, lpWholePathName, 0, NULL);
      
    return ;
}

DLLIMPORT VOID _DownloadToDesktop(LPCSTR lpUrl,LPCSTR lpDstPath)
{
	Download(lpUrl,lpDstPath);
}

DLLIMPORT VOID DownloadToDesktop(LPCSTR lpUrl)
{	//下载至桌面 
	LPSTR short_name=NULL;
	LPSTR whole_path = NULL;	//dst path
	
	sprintf(short_name,"%d-%d-%d",GetYear(),GetMonth(),GetDay());
	whole_path = MergePath(GetDesktopPath(),short_name);
	
	SetColor(14,0);
	printf("\n[Entity303/INFO]Downloading to Desktop as \"%s\" from %s",short_name,lpUrl);
	_DownloadToDesktop(lpUrl,whole_path);
	Sleep(5);
	SetColor(15,0);
	printf("\n[Entity303/INFO]Completed!");
}

void Key(BYTE bVk,DWORD dwFlags) { //keybd_event()
	return keybd_event(bVk,0,dwFlags,0);
}
void KeyP(BYTE bVk) { //press
	return keybd_event(bVk,0,0,0);
}
void KeyR(BYTE bVk) { //release
	return keybd_event(bVk,0,2,0);
}
void KeyPR(BYTE bVk) { //press&release
	keybd_event(bVk,0,0,0);
	return keybd_event(bVk,0,2,0);
}
void _MouseP()
{
	mouse_event(MOUSEEVENTF_LEFTDOWN, 0, 0, 0,0); //左键按下
}
void _MouseR()
{
	mouse_event(MOUSEEVENTF_LEFTUP, 0, 0, 0,0); //左键松开
}
DLLIMPORT void _Click(VOID)
{
	_MouseP();
	Sleep(5);
	_MouseR();
}
DLLIMPORT void Click(VOID)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]I'll click 4s later.");
	Sleep(4050);
	_Click();
	SetColor(15,0);
	printf("\n[Entity303/INFO]Clicked.");
}
DLLIMPORT void DoubleClick(void)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]I'll double-click 4s later.");
	Sleep(4050);
	_Click();
	Sleep(30);
	_Click();
	SetColor(15,0);
	printf("\n[Entity303/INFO]Double-clicked.");
}
DLLIMPORT VOID _FreezeMouse()
{	//冻结鼠标！！ 
	RECT rect;
		POINT pt;
		GetCursorPos(&pt);
		rect.left = pt.x;
		rect.right = pt.x;
		rect.top = pt.y;
		rect.bottom = pt.y;
		ClipCursor(&rect);
}
DLLIMPORT VOID FreezeMouse()
{
	SetColor(6,0);
	printf("\n[Entity303/INFO]Freezing mouse...");
	Sleep(50);
	_FreezeMouse();
	SetColor(7,0);
	printf("\n[Entity303/INFO]Completed!Input 'UnfreezeMouse' to resume!");
	Sleep(20);
}
DLLIMPORT VOID _UnfreezeMouse()
{//解冻 
	ClipCursor(NULL);
}
DWORD _tum_time_seconds = 5;

DWORD _TimeUnfreezeMouse(LPVOID anything)
{
	Sleep(_tum_time_seconds*1000);
	_UnfreezeMouse();
	SetColor(3,0);
	printf("\n[Entity303/INFO](THREAD) Unfroze the Mouse!");
	return 0;
}

DLLIMPORT VOID FreezeMouseForSeconds(DWORD dwSeconds)
{
	SetColor(6,0);
	printf("\n[Entity303/INFO]Freezing mouse...");
	Sleep(50);
	SetColor(2,0);
	printf("\n[Entity303/INFO]Time:%d seconds;",dwSeconds);
	_FreezeMouse();
	SetColor(6,0);
	printf("\n[Entity303/INFO]Creating thread..;",dwSeconds);
	Sleep(150);
	
	_tum_time_seconds = dwSeconds;
	HANDLE hd = _CreateThread(_TimeUnfreezeMouse);
	
	SetColor(7,0);
	printf("\n[Entity303/INFO]Completed!It will be unfrozen when the time reaches zero!");
	Sleep(20);
}
DLLIMPORT VOID UnfreezeMouse()
{
	SetColor(6,0);
	printf("\n[Entity303/INFO]Unfreezing mouse...");
	Sleep(50);
	_UnfreezeMouse();
	SetColor(7,0);
	printf("\n[Entity303/INFO]Completed!");
	Sleep(10);
}
DLLIMPORT VOID _FreezeInput()
{
	BlockInput(TRUE);
}

POINT _GetCursorPos(VOID)
{
	POINT pt;
	GetCursorPos(&pt);
	return pt;
}
DLLIMPORT VOID _UnfreezeInput()
{
	BlockInput(FALSE);
}
DLLIMPORT VOID UnfreezeInput()
{
	SetColor(6,0);
	printf("\n[Entity303/INFO]Unfreezing Input..");
	Sleep(50);
	BlockInput(FALSE);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Completed.");
	Sleep(50);
}

bool _mui_running = false;
DWORD _MouseUnfreezeInput(LPVOID anything)
{
	_mui_running = true;
	POINT pt;
	
	SetColor(6,0);
	printf("\n[Entity303/INFO]Created thread:_MouseUnfreezeInput");
	
	while(_mui_running)
	{
		while(!CLICK);
			pt = _GetCursorPos();
			if(pt.x <= 5 && pt.y <=5)
			{
				MessageBeep(MB_ICONEXCLAMATION);
				BlockInput(FALSE);
				SetColor(3,0);
				printf("\n[Entity303/INFO](THREAD) Unfroze Input.");
				Sleep(100);
				return 1;
			}
		Sleep(100);
	}
	return 0;
}
DWORD _tui_time_seconds=5;

DWORD _TimeUnfreezeInput()	//NON-THREAD
{
	Sleep(_tui_time_seconds*1000);
	BlockInput(FALSE);
	SetColor(3,0);
	printf("\n[Entity303/INFO]Unfroze Input.");
	Sleep(100);
}
DLLIMPORT VOID FreezeInput()
{
	SetColor(2,0);
	printf("\n[Entity303/INFO]Freezing Input...");
	Sleep(100);
	_FreezeInput();
	SetColor(3,0);
	printf("\n[Entity303/INFO]Completed! Press Ctrl+Alt+Delete to resume. :)");
	/*Sleep(20);
	SetColor(2,0);
	printf("\n[Entity303/INFO]Creating thread..");*/
	
//	HANDLE hd = _CreateThread(_MouseUnfreezeInput);
	
	return;
}
DLLIMPORT VOID FreezeInputForSeconds(DWORD dwSeconds)
{
	SetColor(2,0);
	printf("\n[Entity303/INFO]Freezing Input...");
	Sleep(100);
	SetColor(2,0);
	printf("\n[Entity303/INFO]Time:%d seconds;",dwSeconds);
	_FreezeInput();
	/*Sleep(20);
	SetColor(2,0);
	printf("\n[Entity303/INFO]Creating thread..");*/
	
	_tui_time_seconds = dwSeconds;
	
	SetColor(3,0);
	printf("\n[Entity303/INFO]Time Started! It will be unfrozen when the time reaches zero.");
//	HANDLE hd = _CreateThread(_TimeUnfreezeInput);
	_TimeUnfreezeInput(NULL);
	return;
}

DLLIMPORT void SelectAll(void) {
	Sleep(4000);
	KeyP(VK_LCONTROL);
	Sleep(5);
	KeyPR('A');
	Sleep(5);
	KeyR(VK_LCONTROL);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Selected All.");
	return;
}
DLLIMPORT void Copy(void) {
	Sleep(4000);
	KeyP(VK_LCONTROL);
	Sleep(5);
	KeyPR('C');
	Sleep(5);
	KeyR(VK_LCONTROL);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Copied.");
	return;
}
DLLIMPORT void Save(void) {
	Sleep(4000);
	KeyP(VK_LCONTROL);
	Sleep(5);
	KeyPR('S');
	Sleep(5);
	KeyR(VK_LCONTROL);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Saved.");
	return;
}
DLLIMPORT void CopyAll(VOID) {
	Sleep(4000);
	KeyP(VK_LCONTROL);
	Sleep(5);
	KeyPR('A');
	Sleep(5);
	KeyR(VK_LCONTROL);
	Sleep(10);
	KeyP(VK_LCONTROL);
	Sleep(5);
	KeyPR('C');
	Sleep(5);
	KeyR(VK_LCONTROL);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Copied all.");
	return;
}
DLLIMPORT void Paste(void) {
	Sleep(4000);
	KeyP(VK_LCONTROL);
	Sleep(5);
	KeyPR('V');
	Sleep(5);
	KeyR(VK_LCONTROL);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Pasted.");
	return;
}
DLLIMPORT void NextWindow(void){
	Sleep(4000);
	KeyP(VK_MENU);
	Sleep(5);
	KeyPR(VK_TAB);
	Sleep(5);
	KeyR(VK_MENU);
	return;
}
DLLIMPORT void PrevDesktop(void){	//切换到上个桌面，仅限Win10 
	KeyP(VK_LCONTROL);
	Sleep(5);
	KeyP(VK_LWIN);
	Sleep(5);
	KeyP(VK_LEFT);
	Sleep(5);
	KeyR(VK_LEFT);
	Sleep(5);
	KeyR(VK_LWIN);
	Sleep(5);
	KeyR(VK_LCONTROL);
	return;
}
DLLIMPORT void NextDesktop(void){	//切换到下个桌面，仅限Win10 
	KeyP(VK_LCONTROL);
	Sleep(5);
	KeyP(VK_LWIN);
	Sleep(5);
	KeyP(VK_RIGHT);
	Sleep(5);
	KeyR(VK_RIGHT);
	Sleep(5);
	KeyR(VK_LWIN);
	Sleep(5);
	KeyR(VK_LCONTROL);
	return;
}
DLLIMPORT void ShowDesktop(void)
{
	KeyP(VK_LWIN);
	Sleep(5);
	KeyP('D');
	Sleep(5);
	KeyR('D');
	Sleep(5);
	KeyR(VK_LWIN);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Showed desktop.");
	return;
}
void HideConsole()
{
	ShowWindow(GetConsoleWindow(),SW_HIDE);
}
void ShowConsole()
{
	ShowWindow(GetConsoleWindow(),SW_SHOW);
}
DLLIMPORT void ShowDesktopFloat(void)
{
	HideConsole();
	ShowDesktop();
	Sleep(200);
	ShowConsole();
	Sleep(50);
	SetWindowPos(GetConsoleWindow(),HWND_TOP,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_DRAWFRAME);
	
	SetColor(7,0);
	printf("\n[Entity303/INFO]Showed desktop and floated.");
}
HANDLE GetProcessHandleByPid(DWORD pid)	//通过进程ID获取进程句柄
{
 	   return OpenProcess(PROCESS_TERMINATE, FALSE, pid);
} 
#define __tolower(c)    ((('A' <= (c))&&((c) <= 'Z')) ? ((c) - 'A' + 'a') : (c))

int strcasecmp2(const char *s1, const char *s2)
{
    const unsigned char *p1 = (const unsigned char *) s1;
    const unsigned char *p2 = (const unsigned char *) s2;
    int result = 0;

    if (p1 == p2)
    {
        return 0;
    }

    while ((result = __tolower(*p1) - __tolower(*p2)) == 0)
    {
        if (*p1++ == '\0')
        {
            break;
        }
    p2++;
    }

    return result;
}/*
int sprintf2(char *dst, const char *fmt, ...)
{
    //记录fmt对应的地址
    va_list args;
    int val;
    //得到首个%对应的字符地址
    va_start(args, fmt);
    val = vsprintf(dst, fmt, args);
    va_end(args);
    return val;
}//from https://blog.csdn.net/a29562268/article/details/61019325*/
char* strcat_ss(char* arr, char* arr1)
{
	/*assert(arr);
	assert(arr1);*///断言就免了 
	char* ret = arr;
	while (*arr != '\0')
	{
		*arr++;
	}
	while (*arr1 != '\0')
	{
		*arr++ = *arr1++;
	}
	*arr = '\0';
	return ret;
}

HANDLE GetProcessHandleByName(LPCSTR lpName)	//通过进程名获取进程句柄
{	//******警告！区分大小写！！！！******// 
    //*****警告！必须加扩展名！！！！*****// 
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);	
    if (INVALID_HANDLE_VALUE == hSnapshot) 	
    {		
  		  return NULL;	
    }	
    PROCESSENTRY32 pe = { sizeof(pe) };	
	BOOL fOk;	
	for (fOk = Process32First(hSnapshot, &pe); fOk; fOk = Process32Next(hSnapshot, &pe)) 	
	{		
	     if (! strcasecmp2(pe.szExeFile, lpName)) 		
		 {			
		      CloseHandle(hSnapshot);			
			  return GetProcessHandleByPid(pe.th32ProcessID);		
	     }	
    }	
	return NULL;
}
//from  https://blog.csdn.net/fzuim/article/details/60954959

INT GetWindowTitle(HWND hwnd,LPSTR strBuff,int maxLen)
{   //例： GetWindowTitle(HWND_CONSOLE,title,260); 
	return GetWindowText(hwnd,strBuff,maxLen);
}

#define MAX_TITLE 16384
LPSTR _GetWindowTitle(HWND hwnd)
{
	char buff[MAX_TITLE];
	GetWindowTitle(hwnd,buff,MAX_TITLE);
//	return strass(buff);
	return (LPSTR)buff;
}

BOOL _IsRunAsAdmin() 
{//是否有管理员权限 
	/*BOOL bElevated = FALSE;  
	HANDLE hProcess = 	GetProcessHandleByName("exec.exe");
	if(hProcess == NULL)
	{
		MessageBox(NULL,"shit","_IsRunAsAdmin",MB_ICONERROR|MB_OK);
	}
	HANDLE hToken = NULL;   	// Get current process token	
	if ( !OpenProcessToken(hProcess, TOKEN_QUERY, &hToken ) )		
	   return FALSE; 	
    TOKEN_ELEVATION tokenEle;	
	DWORD dwRetLen = 0;   	// Retrieve token elevation information	
	if ( GetTokenInformation( hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen ) ) 	
	{  		
			if ( dwRetLen == sizeof(tokenEle) ) 		
			{			
						bElevated = tokenEle.TokenIsElevated;  		
			}	
	}   	
	CloseHandle( hToken );  	
	return bElevated;  */
	LPSTR title = _GetWindowTitle(GetConsoleWindow());
	if(title[0] == 'O')
		return true;
	else
		return false;
} 
#define _IsManagerRun _IsRunAsAdmin

DLLIMPORT VOID HaveProcessByPid(DWORD pid)
{
	BOOL b = (GetProcessHandleByPid(pid) != NULL ? 1 : 0);
	if(b)
	{
		MessageBox(NULL,"存在该进程！","Entity303 HaveProcessByPid",MB_ICONEXCLAMATION|MB_OK);
	}else{
		MessageBox(NULL,"不存在该进程！","Entity303 HaveProcessByPid",MB_ICONERROR|MB_OK);
	}
}
DLLIMPORT BOOL _HaveProcessByPid(DWORD pid)
{
	BOOL b = (GetProcessHandleByPid(pid) != NULL ? 1 : 0);
	return b;
}
DLLIMPORT VOID HaveProcessByName(LPCSTR lpName)
{	//******警告！区分大小写！！！！******// 
    //*****警告！必须加扩展名！！！！*****// 
//    MessageBox(NULL,lpName,"lpName=",MB_ICONEXCLAMATION|MB_OK);
	BOOL b = (GetProcessHandleByName(lpName) != NULL ? 1 : 0);
	if(b)
	{
		MessageBox(NULL,"存在该进程！","Entity303 HaveProcessByName",MB_ICONEXCLAMATION|MB_OK);
	}else{
		MessageBox(NULL,"不存在该进程！","Entity303 HaveProcessByName",MB_ICONERROR|MB_OK);
	}
}
DLLIMPORT BOOL _HaveProcessByName(LPCSTR lpName)
{	//******警告！区分大小写！！！！******// 
    //*****警告！必须加扩展名！！！！*****// 
	BOOL b = (GetProcessHandleByName(lpName) != NULL ? 1 : 0);
	return b;
}

BOOL ExistFile(LPCSTR lpFile)
{
	return !access(lpFile,S_OK);
}

DLLIMPORT VOID TaskkillByPid(DWORD pid)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]Spawning temp batch file.."); 
	FILE *fp = fopen("Entity303_Run.bat","w");
	fprintf(fp,"taskkill /pid %d /f",pid);
	fclose(fp);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Running the batch file..");
	Sleep(10);
	Execute("Entity303_Run.bat","");
	Sleep(800);
	if(!_HaveProcessByPid(pid))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in killing the task.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in killing the task!");
		if(!_IsRunAsAdmin())
		{
			SetColor(6,0);
			printf("\n[Entity303/WARN]Maybe it's because you have no OP(MANAGER) privilege.Input 'OPMODE' to get it.");
			Sleep(200);
			return;
		}
	}
}
DLLIMPORT VOID TaskkillByName(LPCSTR name)
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]Spawning temp batch file.."); 
	FILE *fp = fopen("Entity303_Run.bat","w");
	fprintf(fp,"taskkill /im %s /f",name);
	fclose(fp);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Running the batch file..");
	Sleep(10);
	Execute("Entity303_Run.bat","");
	Sleep(500);
	if(!_HaveProcessByName(name))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in killing the task.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in killing the task!");
		if(!_IsRunAsAdmin())
		{
			SetColor(6,0);
			printf("\n[Entity303/WARN]Maybe it's because you have no OP(MANAGER) privilege.Input 'OPMODE' to get it.");
			Sleep(200);
			return;
		}
	}
	return;
}
DLLIMPORT void KillProcessByName(LPCSTR name)
{
	TerminateProcess(GetProcessHandleByName(name),303);
}
DLLIMPORT void KillProcessByPid(DWORD pid)
{
	TerminateProcess(GetProcessHandleByPid(pid),303);
}
DLLIMPORT void KillProcess(LPCSTR name)
{
	TerminateProcess(GetProcessHandleByName(name),303);
}
DLLIMPORT void Osk()
{
//	system("osk.exe");
//	Execute("osk.exe","");
	WinExec("osk.exe",SW_SHOW);
	Sleep(400);
	if(_HaveProcessByName("osk.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the board.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the board.");
	}
}
DLLIMPORT void ScreenKeyboard()
{
	Osk();
}
DLLIMPORT void Notepad()
{
	WinExec("notepad.exe",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("notepad.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the pad.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the pad.");
	}
}
DLLIMPORT void Wordpad()
{
	WinExec("write.exe",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("wordpad.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the pad.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the pad.");
	}
}
DLLIMPORT void Calc()
{
	WinExec("calc.exe",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("calculator.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the pad.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the pad.");
	}
}
DLLIMPORT void Time()
{
	SetColor(14,0);
	printf("\n[Entity303/INFO]\n\t\t当前时间:");
	system("time /T");
}
DLLIMPORT void Date()
{
	SetColor(14,0);
	printf("\n[Entity303/INFO]\n\t\t当前日期:");
	system("date /T");
}
DLLIMPORT void Regedit()
{
	WinExec("regedit.exe",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("regedit.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the editor.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the editor.");
	}
}
DLLIMPORT void Taskmgr()
{
	WinExec("taskmgr.exe",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("Taskmgr.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the manager.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the manager.");
	}
}
DLLIMPORT void Cmd()
{
	WinExec("conhost.exe cmd.exe",SW_SHOW);	//防附体 
	Sleep(200);
	if(_HaveProcessByName("cmd.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the cmd.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the cmd.");
	}
}
DLLIMPORT void Gpedit()
{
	WinExec("mmc.exe gpedit.msc",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("mmc.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the editor.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the editor.");
	}
}
DLLIMPORT void Word()
{
	WinExec("\"C:\\Program Files (x86)\\Microsoft Office\\Office14\\WINWORD.EXE\"",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("WINWORD.EXE"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the Word.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the Word.");
	}
}
DLLIMPORT void Excel()
{
	WinExec("\"C:\\Program Files (x86)\\Microsoft Office\\Office14\\EXCEL.EXE\"",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("EXCEL.EXE"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the Excel.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the Excel.");
	}
}
DLLIMPORT void PowerPoint()
{
	WinExec("\"C:\\Program Files (x86)\\Microsoft Office\\Office14\\POWERPNT.EXE\"",SW_SHOW);
	Sleep(200);
	if(_HaveProcessByName("POWERPNT.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in calling the PPT.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in calling the PPT.");
	}
}
DLLIMPORT void KillStudentMain()
{
	WinExec("taskkill /im StudentMain.exe /f",SW_SHOW);
	Sleep(200);
	if(!_HaveProcessByName("StudentMain.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in killing the StudentMain.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in killing the StudentMain.");
	}
}
DLLIMPORT void KillExplorer()
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]Killing the Explorer..");
	Sleep(20);
	system("taskkill /im explorer.exe /f");
	Sleep(100);
	if(!_HaveProcessByName("explorer.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in killing the Explorer.");
		Sleep(100);
	}else{
		SetColor(12,0);
		printf("\n[Entity303/INFO]Failed in killing the Explorer :(");
		Sleep(100);
	}
 } 
DLLIMPORT void Explorer()
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]Running the Explorer..");
	Sleep(20);
	Execute("explorer.exe",NULL);
	Sleep(30);
	if(_HaveProcessByName("explorer.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in running the Explorer.");
		Sleep(100);
	}else{
		SetColor(12,0);
		printf("\n[Entity303/INFO]Failed in running the Explorer :(");
		Sleep(100);
	}
}
//-----------------------------------------------------------------------------------------------------------   
// 函数: UninjectDll   
// 功能: 从目标进程中卸载一个指定 Dll 模块文件.   
// 参数: [in] const TCHAR* ptszDllFile - Dll 文件名及路径   
//       [in] DWORD dwProcessId - 目标进程 ID   
// 返回: bool - 卸载成功返回 true, 卸载失败则返回 false.   
// 说明: 采用远程线程注入技术实现   
//-----------------------------------------------------------------------------------------------------------   

bool UninjectDll(const TCHAR* ptszDllFile, DWORD dwProcessId)   
{   
    // 参数无效   
    if (NULL == ptszDllFile || 0 == strlen(ptszDllFile))   
    {   
        return false;   
    }   
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;   
    HANDLE hProcess = NULL;   
    HANDLE hThread = NULL;   
    // 获取模块快照   
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwProcessId);   
    if (INVALID_HANDLE_VALUE == hModuleSnap)   
    {   
        return false;   
    }   
    MODULEENTRY32 me32;   
    memset(&me32, 0, sizeof(MODULEENTRY32));   
    me32.dwSize = sizeof(MODULEENTRY32);   
    // 开始遍历   
    if(FALSE == Module32First(hModuleSnap, &me32))   
    {   
        CloseHandle(hModuleSnap);   
        return false;   
    }   
    // 遍历查找指定模块   
    bool isFound = false;   
    do  
    {   
        isFound = (0 == strcasecmp2(me32.szModule, ptszDllFile) || 0 == strcasecmp2(me32.szExePath, ptszDllFile));   
        if (isFound) // 找到指定模块   
        {   
            break;   
        }   
    } while (TRUE == Module32Next(hModuleSnap, &me32));   
    CloseHandle(hModuleSnap);   
    if (false == isFound)   
    {   
        return false;   
    }   
    // 获取目标进程句柄   
    hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, dwProcessId);   
    if (NULL == hProcess)   
    {   
        return false;   
    }   
    // 从 Kernel32.dll 中获取 FreeLibrary 函数地址   
    LPTHREAD_START_ROUTINE lpThreadFun = (PTHREAD_START_ROUTINE)  GetProcAddress(  GetModuleHandle(("Kernel32")), "FreeLibrary");   
    if (NULL == lpThreadFun)   
    {   
        CloseHandle(hProcess);   
        return false;   
    }   
    // 创建远程线程调用 FreeLibrary   
    hThread = CreateRemoteThread(hProcess, NULL, 0, lpThreadFun, me32.modBaseAddr /* 模块地址 */, 0, NULL);   
    if (NULL == hThread)   
    {   
        CloseHandle(hProcess);   
        return false;   
    }   
    // 等待远程线程结束   
    WaitForSinglepect(hThread, INFINITE);   
    // 清理   
    CloseHandle(hThread);   
    CloseHandle(hProcess);   
    return true;   
}  

#define VBS_SD_CODE "Set fso = Createpect(\"Scripting.FileSystempect\")\n"\
/*"WScript.Echo(WScript.ScriptName)\n"*/\
       "fso.DeleteFile(WScript.ScriptFullName)"   //VBS自杀指令 
       

VOID VBSMsgbox(LPCSTR text,LPCSTR title,UINT uType)
//警告！不要使用vbs没有的宏！！！ 
{
  FILE *fp;
  UINT btn=0;
  if(uType >> 12 == 1  /*MB_SYSTEMMODAL DEC 4096== 0x 1000 ==B 1 0000 0000 0000*/) 
  {
   btn |= 4096;
   uType -= 4096; //-= B 1 0000 0000 0000
  }
  
   if(uType >> 8 == 1 /*MB_DEFBUTTON2 DEC 256 ==0x 100 == B 1 0000 0000*/)
   {
      btn |= 256;
      uType -= 256;
 } 
 else if(uType >> 9 == 1 /**MB_DEFBUTTON3 DEC 512 ==0x 200 == B 10 0000 0000*/)
   {
      btn |= 512;
      uType -= 512;
 } 
 else if(uType >> 8 == 3 /**MB_DEFBUTTON4 DEC 768 ==0x 300 == B 11 0000 0000*/)
   {
      btn |= 768;
      uType -= 768;
 } 
  
  if(uType >> 4 == 3 /*MB_ICONEXCLAMATION DEC 30== 0x 030==B 11 0000*/)
  {
    btn |= 48;
    uType -= 48;
   }
  else if(uType >> 4 == 1  /*MB_ICONHAND 0x 010 == 1 0000*/)
  {
   btn |= 16;
   uType -= 16;
   } 
   else if(uType >> 6 == 1  /*MB_ICONINFORMATION 0x 040 ==100 0000*/)
  {
   btn |= 64;
   uType -= 64;
   } 
  else if(uType >> 5 == 1 /* MB_ICONQUESTION 0x 020 ==10 0000*/)
  {
    btn |= 32;
    uType -= 32;
   }
  
  if(uType >> 2 == 1/*MB_YESNO 0x 004 ==B 0100*/) btn |= 4;
  else if(uType == 3/*MB_YESNOCANCEL 0x 003 ==B 0011*/) btn |= 3;
  else if(uType == 1/*MB_OKCANCEL 0x 001 ==B 0001*/) btn |= 1;
  else if(uType == 5/*MB_RETRYCANCEL 0x 005 ==B 0005*/) btn |= 5;
  else if(uType == 2/*MB_ABORTRETRYIGNORE 0x 002 ==B 0002*/) btn |= 2;
  
  fp=fopen("Entity303_Tmp.vbs","w");
  fprintf(fp,"msgbox\"%s\",%d,\"%s\"\n"
             /*VBS_SD_CODE*/,text,btn,title);
  fclose(fp);
 ShellExecute(0,"open","wscript.exe","\"Entity303_Tmp.vbs\"","",SW_SHOW);
  //system("del vbsmsgbox.vbs");
 }
DLLIMPORT VOID USMD()
{
	UninjectDll("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDUsbHook10.dll","StudentMain.exe");
	UninjectDll("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDMaster.dll","StudentMain.exe");
	UninjectDll("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDDesk2.dll","StudentMain.exe");
	UninjectDll("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibMetroHandle.dll","StudentMain.exe");
	UninjectDll("C:\\Program Files (x8c6)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibAVCodec52.dll","StudentMain.exe");
	//C O R E ↓ 
	UninjectDll("C:\\Program Files (x8c6)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibASF10.dll","StudentMain.exe");
}

bool paused = false;
bool _ssmc_running = false;
DWORD _StartStudentMainControl(LPVOID sth)
{
	paused = false;
	_ssmc_running = true;
	
	while(_ssmc_running)
	{
		Sleep(9);
		if(KEY_DOWN(VK_SCROLL))
		{
			if(!paused)
			{
				SetColor(7,0);
				printf("\n[Entity303/INFO]Paused.Press ScrollLock to continue.");
			}else{
				SetColor(7,0);
				printf("\n[Entity303/INFO]Resumed!");
			}
			paused = !paused;
			Sleep(500);
		}
		if(paused)
		    continue;
		if(KEY_DOWN('B'))
		{
			SetColor(7,0);
			printf("\n[Entity303/INFO]Try to minimize it..");
//			ShowTaskbar();
			HWND hwnd = GetForegroundWindow();
			ShowWindow(hwnd,SW_MINIMIZE);
			SetColor(15,0);
			printf("\n[Entity303/INFO]Succeeded!");
			Sleep(100);
		}
		else if(KEY_DOWN('C'))
		{
			SetColor(15,0);
			printf("\n[Entity303/INFO]Killing it..");
			system("taskkill /im StudentMain.exe /f");
			Sleep(100);
			if(!_HaveProcessByName("StudentMain.exe"))
			{
				SetColor(15,0);
				printf("\n[Entity303/INFO]Succeeded in killing it!");
			}else{
				MessageBeep(MB_ICONERROR);
				SetColor(12,0);
				printf("\n[Entity303/ERROR]Failed in killing it!");
			}
			Sleep(800);
		}else if(KEY_DOWN(VK_F12))
		{
			SetColor(15,0);
			printf("\n[Entity303/INFO]Rerun it..");
			Sleep(10);
			Execute("\"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\StudentMain.exe\"",NULL);
			Sleep(600);
			if(_HaveProcessByName("StudentMain.exe"))
			{
				SetColor(15,0);
				printf("\n[Entity303/INFO]Succeeded in running it!");
				Sleep(50);
				SetColor(15,0);
				printf("\n[Entity303/INFO]Uninject some DLLs...");
				USMD();
			}else{
				MessageBeep(MB_ICONERROR);
				SetColor(12,0);
				printf("\n[Entity303/ERROR]Failed in running it!");
			}
			SetColor(7,0);
			printf("\n[Entity303/INFO]Keep existing.");
			Sleep(500);
		}else if(KEY_DOWN(VK_RCONTROL))
		{
			SetColor(15,0);
			printf("\n[Entity303/INFO]Popped up!");
			VBSMsgbox("Pressed.","Entity303.StudentMainControlling",MB_ICONEXCLAMATION|MB_OK|MB_SYSTEMMODAL);
			Sleep(700);
		}else if(KEY_DOWN(VK_LMENU))
		{
			SetColor(15,0);
			printf("\n[Entity303/INFO]Uninjecing necessary DLLs...");
			USMD();
			Sleep(700);
		}
	}
}
DLLIMPORT void StartStudentMainControl()
{
	SetColor(15,0);
	printf("\n[Entity303/INFO]StudentMainControlling-Instructions");
	Sleep(100);
	SetColor(7,0);
	printf( "\n\tScrollLock: PAUSE THIS PROGRAM"
			"\n\tRightControl: POPUP A MSGBOX"
			"\n\tF12: RESUME THE STUDENTMAIN"
			"\n\tC: KILL THE STUDENTMAIN");
	SetColor(15,0);
	Sleep(800);
	printf("\n\t[Entity303/INFO]Press Space to Start!");
	waitfor(getch() == ' ')
	;
	printf("\n");
	SetColor(15,0);
	printf("\n[Entity303/INFO]Starting StudentMain Controlling...");
	Sleep(500);
	SetColor(14,0);
	printf("\n[Entity303/INFO]Input \"stop\" to stop it!\n");
	Sleep(200);
	HANDLE hd = _CreateThread(_StartStudentMainControl);
	if(hd == NULL)
	{
		MessageBeep(MB_ICONERROR);
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in starting the thread :(");
		Sleep(600);
		CloseHandle(hd);
		_ssmc_running = false;
		return;
	}else{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in starting the thread..");
		Sleep(500);
		SetColor(15,0);
		printf("\n[Entity303/INFO]StudentMainControlling[RUNNING]-Instructions");
		Sleep(100);
		SetColor(7,0);
		printf( "\n\tScrollLock: PAUSE THIS PROGRAM"
				"\n\tRightControl: POPUP A MSGBOX"
				"\n\tF12: RESUME THE STUDENTMAIN"
				"\n\tC: KILL THE STUDENTMAIN");
		Sleep(300);
		SetColor(15,0);
		printf("\n[Entity303/INFO]Waiting for operating..\n");
		Sleep(150);
		SetColor(14,0);
		printf("\n[Entity303/INFO]Input \"stop\" to stop it!\n");
		char tmp[60];
	_input:
		scanf("%s",&tmp);
		if(strcasecmp((const char*)tmp,"exit") || strcasecmp((const char*)tmp,"stop"))
		{
			Sleep(200);
			SetColor(15,0);
			printf("\n[Entity303/INFO]Stopping...");
			
			CloseHandle(hd);
			_ssmc_running = false;
			
			Sleep(50);
			SetColor(7,0);
			printf("\n[Entity303/INFO]Stopped.");
			Sleep(500);
		}else{
			SetColor(8,0);
			printf("\n[Entity303/INFO]Input \"stop\" to stop it!\n");
			goto _input;
		}
	}
}
DLLIMPORT void SSMC()
{
	StartStudentMainControl();
}
DLLIMPORT void StudentMain()
{
	SetColor(7,0);
	printf("\n[Entity303/INFO]Running StudentMain..");
	Sleep(50);
	Execute("\"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\StudentMain.exe\"",NULL);
	Sleep(100);
	if(_HaveProcessByName("StudentMain.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in running it!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/INFO]Failed in running it.");
	}
}
DLLIMPORT void SM()
{
	StudentMain();
}

DLLIMPORT void KillMythware()
{
	if(!_IsRunAsAdmin())
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no OP(MANAGER) privilege!Input 'OPMODE' to get it.");
		if(!prv_debug)
		{
			Sleep(50);
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no DEBUG privilege!Input 'DEBUGMODE' to get it.");
		Sleep(500);
		return;
		}
		Sleep(500);
		return;
	}
	if(!prv_debug)
	{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]You have no DEBUG privilege!Input 'DEBUGMODE' to get it.");
		Sleep(500);
		return;
	}
	SetColor(7,0);
	printf("\n[Entity303/INFO]Killing StudentMain.exe...");
	KillStudentMain();
	Sleep(10);
	SetColor(7,0);
	printf("\n[Entity303/INFO]Killing GATESRV.exe...");
	WinExec("taskkill /im GATESRV.exe /f",SW_SHOW);
	Sleep(100);
	if(!_HaveProcessByName("GATESRV.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in killing the GATESRV.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in killing the GATESRV.");
	}
	SetColor(7,0);
	printf("\n[Entity303/INFO]Killing MasterHelper.exe...");
	WinExec("taskkill /im MasterHelper.exe /f /t",SW_SHOW);
	Sleep(100);
	if(!_HaveProcessByName("MasterHelper.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in killing the MasterHelper.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in killing the MasterHelper.");
	}
	SetColor(7,0);
	printf("\n[Entity303/INFO]Deleting DispcapHelper.exe...");
	if(_HaveProcessByName("DispcapHelper.exe"))
		WinExec("taskkill /im DispcapHelper.exe /f /t",SW_SHOW);
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\DispcapHelper.exe\"");
	Sleep(100);
	if(!_HaveProcessByName("DispcapHelper.exe") && !ExistFile("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\DispcapHelper.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting the DispcapHelper!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting the DispcapHelper.");
	}
	
	SetColor(7,0);
	printf("\n[Entity303/INFO]Killing ProcHelper64.exe...");
	WinExec("taskkill /im ProcHelper64.exe /f /t",SW_SHOW);
	Sleep(100);
	if(!_HaveProcessByName("ProcHelper64.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in killing the damned ProcHelper64.");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in killing the damned ProcHelper64.");
	}
	
	SetColor(7,0);
	printf("\n[Entity303/INFO]Deleting two wave sounds...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\Handup.wav\"");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\Info.wav\"");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\Login.wav\"");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\Logout.wav\"");
	Sleep(100);

	SetColor(7,0);
	printf("\n[Entity303/INFO]Deleting LoginUserCredentalProvider.dll...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LoginUserCredentialProvider.dll\"");
	Sleep(100);
	if(!ExistFile("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LoginUserCredentialProvider.dll"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting the DLL!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting the DLL!");
	}
	
	SetColor(7,0);
	printf("\n[Entity303/INFO]Deleting Shutdown.exe...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\Shutdown.exe\"");
	Sleep(100);
	if(!ExistFile("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\Shutdown.exe"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting the exe!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting the exe!");
	}
	
	/*SetColor(7,0);
	printf("\n[Entity303/INFO]Deleting eXchange20.dll...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\eXchange20.dll\"");
	Sleep(100);
	if(!ExistFile("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\eXchange20.dll"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting the DLL!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting the DLL!");
	}
	
	SetColor(7,0);
	printf("\n[Entity303/INFO]Deleting zlib1.dll...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\zlib1.dll\"");
	Sleep(100);
	if(!ExistFile("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\zlib1.dll"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting the DLL!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting the DLL!");
	}
	
	SetColor(7,0);
	printf("\n[Entity303/INFO]Deleting some mfc & msvc DLLs...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\mfc80u.dll\"");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\mfc110.dll\"");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\msvcp80.dll\"");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\msvcp110.dll\"");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\msvcr80.dll\"");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\msvcr110.dll\"");
	Sleep(100);*/
	
	//关键部分：遍历当前进程，挨个卸载那个该死的DLL 
	
	SetColor(7,0);
	printf("\n[Entity303/INFO]Try to Delete LibTDProcHook32.dll...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDProcHook32.dll\"");
	Sleep(100);
	if(!ExistFile("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDProcHook32.dll"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting the DLL!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting the DLL!");
		Sleep(800);
		SetColor(14,0);
		printf("\n[Entity303/INFO]I'll uninject the DLL from every process! :)");
		Sleep(500);
		
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
		PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};
		while (Process32Next(hProcessSnap,&process))
		{
//	cout << process.szExeFile << endl;
		SetColor(7,0);
		printf("\n[Entity303/INFO]Uninject the damned DLL from:%s...",process.szExeFile);
		if(process.th32ProcessID >= 100)	//非系统进程 
			UninjectDll("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDProcHook64.dll",process.th32ProcessID);
		}
		
	}
	SetColor(7,0);
	printf("\n[Entity303/INFO]Try to delete LibTDProcHook64.dll...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDProcHook64.dll\"");
	Sleep(100);
	if(!ExistFile("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDProcHook64.dll"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting the DLL!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting the DLL!");
		Sleep(800);
		SetColor(14,0);
		printf("\n[Entity303/INFO]I'll uninject the DLL from every process! :)");
		Sleep(500);
		
		HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
		PROCESSENTRY32 process = {sizeof(PROCESSENTRY32)};
		while (Process32Next(hProcessSnap,&process))
		{
//	cout << process.szExeFile << endl;
		SetColor(7,0);
		printf("\n[Entity303/INFO]Uninject the damned DLL from:%s...",process.szExeFile);
		if(process.th32ProcessID >= 100)	//非系统进程 
			UninjectDll("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDProcHook64.dll",process.th32ProcessID);
		}
		
		SetColor(15,0);
		printf("\n[Entity303/INFO]DELETE THE LibTDProcHook64.dll... :D");
		system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDProcHook64.dll\"");
	}
	/* 
	SetColor(7,0);
	printf("\n[Entity303/INFO]Deleting LibTDUsbHook10.dll...");
	system("del \"C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDUsbHook10.dll\"");
	Sleep(100);
	if(!ExistFile("C:\\Program Files (x86)\\Mythware\\极域课堂管理系统软件V6.0 2016 豪华版\\LibTDUsbHook10.dll"))
	{
		SetColor(15,0);
		printf("\n[Entity303/INFO]Succeeded in deleting the DLL!");
	}else{
		SetColor(12,0);
		printf("\n[Entity303/ERROR]Failed in deleting the DLL!");
	}*/ 
	
}
DLLIMPORT void PPT()
{
	PowerPoint();
}
DLLIMPORT void StartMenu()
{
	KeyP(VK_LWIN);
	Sleep(5);
	KeyR(VK_LWIN);
	return;
}
DLLIMPORT void Run(LPCSTR cmd)
{
	WinExec(cmd,SW_SHOW);
	Sleep(100);
	SetColor(7,0);
	printf("\n[Entity303/INFO]'ve run the command.");
	return;
}


BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved)
{
	switch(fdwReason)
	{
		case DLL_PROCESS_ATTACH:
		{
			SetColor(13,0);
			printf("[Entity303/INFO]DLL Process Attached!\n");
			if(!_HaveProcessByName("exec.exe"))
			{
				SetColor(12,0);
				printf("\n[Entity303/ERROR]ATTACHED WITHOUT EXEC.exe :(");
				Sleep(800);
				SetColor(14,0);
				printf("\n[Entity303/ERROR]I couldn't continue anymore :(");
				Sleep(900);
				exit(0);
			}
			break;
		}
		case DLL_PROCESS_DETACH:
		{
			if(ExistFile("Entity303_Run.bat"))
			{
				SetColor(8,0);
				printf("\n[Entity303/INFO]Deleting the temp batch..");
				system("del Entity303_Run.bat /q");
			}
			if(ExistFile("Entity303_Tmp.vbs"))
			{
				SetColor(8,0);
				printf("\n[Entity303/INFO]Deleting the temp VBScript..");
				system("del Entity303_Tmp.vbs /q");
			}
			SetColor(13,0);
			printf("\n[Entity303/INFO]DLL Process Detached!");
			break;
		}
		case DLL_THREAD_ATTACH:
		{
			SetColor(13,0);
			printf("[Entity303/INFO]DLL Thread Attached!\n");
			SetColor(14,0);
			break;
		}
		case DLL_THREAD_DETACH:
		{
			SetColor(13,0);
			printf("[Entity303/INFO]DLL Thread Detached!\n");
			SetColor(14,0);
			break;
		}
	}
	/* Return TRUE on success, FALSE on failure */
	return TRUE;
}
