#include <stdcjz.h>
//using namespace std;
//#define PASSWORD GetHour()+GetMonth()+1
#define PASSWORD1 "_noexcept"
#define PASSWORD2 ToC_Str(GetHour()+GetMonth()+(GetDay()%2==1?1:0))//h + mon + d%2

typedef DWORD (*DLL_FUNC)();
typedef DWORD (*DLL_STR_FUNC)(LPCSTR);
typedef DWORD (*DLL_DWORD_FUNC)(DWORD);
typedef DWORD (*DLL_LPVOID_FUNC)(LPVOID);
#define CALLDLLFUNC(sf) DLL_FUNC sf;\
						sf = (DLL_FUNC) GetProcAddress(hDll, #sf); \
						if(sf != NULL)\
						{\
							printf("\n[exec/INFO]Succeeded in calling the func '%s'",#sf);\
							sf();\
						}else{\
							printf("\n[exec/ERROR]Cannot get the func!");\
						}
#define CALLDLLFUNC2(sf) auto sf = GetProcAddress(hDll, #sf); \
						if(sf != NULL)\
						{\
							printf("\n[exec/INFO]Succeeded in calling the func '%s'",#sf);\
							sf();\
						}else{\
							printf("\n[exec/ERROR]Cannot get the func!");\
						}
HINSTANCE hDll;
bool opmode;

void OPMODE()
{
	SetColor(15,0);
	cout<<"\n[exec/INFO]Releasing the DLL...";
	FreeLibrary(hDll); 
	
	Sleep(50);
	SetColor(14,0);
	cout<<"\n[exec/INFO]Getting Manager Priority...";
	Sleep(20);
	SetColor(11,0);
	cout<<"\n[exec/INFO]Running myself on OPMODE...";
	Sleep(100);
	ManagerRun(_pgmptr,NULL);
	Sleep(150);
	SetColor(7,0);
	cout<<"\n[exec/INFO]Exitting...";
	Sleep(800);
	SetColor(8,0);
	exit(0);
}
int main()
{
//	DLL_FUNC HelloWorld,About;
//	SetColor(7,0);
	opmode = false;
	SetColor(15,0);
	cout<<"exec - a program that tests the Entity303.DLL.\n";
	Sleep(500);
	if(IsManagerRun())
	{
		SetWindowTitle(GetConsoleWindow(),"OPMODE: exec");
		opmode = true;
//		string pw;
//		int pw;
		string s;
		SetColor(14,0);
		cout<<"\n[exec/INFO]'ve got the Manager Priority!";
		SetColor(11,0);
		prints("\n\nINPUT THE PASSWORD: ",25);
		/*SetColor(8,0);
		cin>>pw;*/
		s = PasswordString("`",cout);
//		pw = stoi(s);
//		cout<<"Your password:"<<s<<endl;
		if(s != PASSWORD1 && s != PASSWORD2)
		{
			MessageBeep(MB_ICONERROR);
			SetColor(12,0);
			cout<<"\n[exec/ERROR]Incorrect Password!";
			Sleep(900);
			SetColor(14,0);
			cout<<"\n[exec/WARN]**********************************************";
			Sleep(20);
			cout<<"\n[exec/WARN]DO NOT USE THIS WITHOUT NOEXCEPT's PERMISSION!";
			Sleep(20);
			cout<<"\n[exec/WARN]**********************************************";
			Sleep(600);
			SetColor(12,0);
			cout<<"\n[exec/INFO]Exitting...";
			Sleep(500);
			SetColor(4,0);
			exit(0);
			return -1;
		}
		SetColor(10,0);
		cout<<"\n[exec/INFO]Correct Password :D";
		MessageBeep(MB_ICONEXCLAMATION);
		Sleep(400);
		SetColor(15,0);
		cout<<"\n[exec/INFO]Welcome,noexcept :D";
		Sleep(600);
		SetColor(15,0);
		cout<<"\n\n[exec/INFO] (***RUNNING ON OPMODE!***)";
	}else{
		SetWindowTitle(GetConsoleWindow(),"exec");
	}
	SetColor(7,0);
	cout<<"\n\n[exec/INFO]Loading the DLL...\n";
	Sleep(70);
	if(!ExistFile("Entity303.dll"))
	{
		MessageBeep(MB_ICONERROR);
		SetColor(12,0);
		cout<<"\n[exec/INFO]Cannot find Entity303.dll :(";
		Sleep(500);
		SetColor(7,0);
		printf("\n[exec/INFO]Exitting...");
		Sleep(1000);
		SetColor(8,0);
		return 0;
	}
	
	hDll = LoadLibrary("Entity303.dll");
	
	if(hDll != NULL)
	{
		/*HelloWorld = (DLL_FUNC) GetProcAddress(hDll, "HelloWorld"); 
		if(HelloWorld != NULL)
		{
			printf("\n[exec/INFO]Succeeded in calling the func 'HelloWorld!'");
			HelloWorld();
		}else{
			printf("\n[exec/ERROR]Cannot get the func!");
		}
		CALLDLLFUNC2(About);*/
		Sleep(55);
		SetColor(15,0);
		cout<<"\n[exec/INFO]Succeeded in loading the DLL!\n";
		while(1)
		{
			string s;
			SetColor(10,0);
			printf("\n>");
			SetColor(14,0);
			cin>>s;
//			s = "About";
			SetColor(7,0);
			if(s == "exit" || s == "quit" || s == "Exit" || s == "Quit")
				break;
			else if(s == "OPMODE" || s == "OPMode" || s == "opmode" || s == "ManagerMode" || s == "MANAGERMODE")
			{
				if(!opmode)
				{
					MessageBeep(MB_ICONINFO);
					OPMODE();
				}else{
					MessageBeep(MB_ICONERROR);
					SetColor(7,0);
					cout<<"\n[exec/INFO]Now 've already been running on OPMODE!";
				}
				return 0;
			}
			DLL_FUNC Func;
			DLL_STR_FUNC StrFunc;
			string str;
			DLL_DWORD_FUNC DwordFunc;
			DWORD dword;
			
			DLL_LPVOID_FUNC Ptr_Func=NULL;		//º¯ÊýÖ¸Õë 
			UINT type=0;
			
			if(s == "HaveProcessByName" || s == "TaskkillByName" || s == "Run" || s == "DeleteDrive")
			{
				StrFunc = (DLL_STR_FUNC)GetProcAddress(hDll, s.c_str()); 
				Ptr_Func = (DLL_LPVOID_FUNC) StrFunc;
				type = 1;
//				SetColor(11,0);
				cin>>str;
			}else if(s == "HaveProcessByPid"|| s == "TaskkillByPid" || s == "SystemSleep" || s == "FreezeMouseForSeconds" || s == "FreezeInputForSeconds"){
				DwordFunc = (DLL_DWORD_FUNC)GetProcAddress(hDll,s.c_str());
				Ptr_Func = (DLL_LPVOID_FUNC) DwordFunc;
				type = 2;
//				SetColor(10,0);
				cin>>dword;
			}else{
				Func = (DLL_FUNC)GetProcAddress(hDll,s.c_str());
				Ptr_Func = (DLL_LPVOID_FUNC) Func;
				type = 3;
			}
			if(Ptr_Func != NULL)
			{
				printf("\n[exec/INFO]Succeeded in calling the func '%s':\n",s.c_str());
				
				if(type == 1)
					(Ptr_Func)((LPVOID)str.c_str());
				else if(type == 2)
					(Ptr_Func)((LPVOID)dword);
				else
					(Ptr_Func)(NULL);
			}else{
				SetColor(12,0);
				printf("\n[exec/ERROR]Invalid function name!!");
				SetColor(7,0);
			}
		}
		SetColor(15,0);
		printf("\n[exec/INFO]Releasing the DLL...");
		
		FreeLibrary(hDll); 
	}else{
		SetColor(12,0);
		printf("\n[exec/ERROR]Failed in loading the DLL!");
		SetColor(7,0);
	}
	Sleep(200);
	SetColor(7,0);
	printf("\n[exec/INFO]Exitting...");
	Sleep(1000);
	SetColor(8,0);
	return 0;
}
