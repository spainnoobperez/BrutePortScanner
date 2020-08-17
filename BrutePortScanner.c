#include <winsock.h>
#include <stdio.h>
#include <commctrl.h>
#include "Resource.h"

#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib,"WSOCK32.lib")
#pragma comment(lib,"COMCTL32.lib")
typedef	struct tagThread {
    DWORD dwAddr;
    WORD wPort;
} THREADINFO;

typedef	struct tagItem {
    DWORD dwAddr;
    WORD wPort;
    LPSTR lpstrBanner;
} ITEMINFO;
HWND g_hWnd;
HWND g_hwndListView;
HWND g_hwndStatus;
HWND g_hwndToolTip;
HMENU g_hMenu;
HHOOK g_hHook;
HINSTANCE g_hInst;
HCURSOR g_hCursor;
HBITMAP g_hBitmap[6];

BYTE byteIP[4];
FILE *fpFile;
POINT ptCur;
IN_ADDR iaServer;
THREADINFO thdINFO[300];

BOOL isGetBanner;
BOOL isUsePortRange;
BOOL isUsePortList;
BOOL isUseResultIP;
BOOL isStopForce;
BOOL isKeepHistroy		= TRUE;
BOOL isNoAsk;

int i;
int nTimeOut;
int nThreadNum;
int nScannedPort;
int nStartPort;
int nEndPort;
int nPort[100];
int nPortCount;
int nSkipHost;
int nItemCount;
DWORD dwStartIP;
DWORD dwEndIP;
DWORD dwThreadID;

char *p;
char strTemp[600];
const char c_szResolve[]		= "Parsing domain name...";
const char c_szGetBanner[]		= "Getting ID...";
const char c_szCancelBanner[]	= "Scan aborted, give up the mark";
const char c_szWelcome[]		= "Hola amigo!";
const char *c_szToolTip[]		= {
    "Starting IP address",
    "Ending IP address",
    "Choose whether to use port range",
    "Choose whether to use the port list",
    "Starting port",
    "Ending port",
    "Port list, use commas (,) to separate different ports",
    "Number of scanning threads, 100 threads by default",
    "Connection timeout time, default 2 seconds",
    "This is a scan result window, please right click to bring up a pop-up menu.",
    "Start scanning",
    "Stop scanning",
    "https://www.rodrigueztech.ml",
    "mailto:LosAngeles@gmail.com"
};

BOOL WINAPI LoadResult(char	*strFileName);
BOOL WINAPI SaveResult(char	*strFileName, BOOL isSaveSelected);

void WINAPI StartScan();
void WINAPI ResolveDomain();
void WINAPI ScanThread(int intCurThread);

void WINAPI On_InitDialog();
void WINAPI On_Command(WPARAM wParam);
void WINAPI On_NoTify(WPARAM wParam, LPARAM lParam);
void WINAPI On_DrawItem(WPARAM wParam, LPARAM lParam);

int	APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE	hPrevInstance, LPSTR lpCmdLine,	int	nCmdShow);
LRESULT	CALLBACK		MouseProc(int nCode, WPARAM wParam, LPARAM	lParam);
LRESULT CALLBACK		HyperLinkProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
static int CALLBACK		CompareFunc(LPARAM lParam1,	LPARAM lParam2,	LPARAM lParamSort);
static BOOL	CALLBACK	AboutDlgProc(HWND	g_hWnd,	UINT msg, WPARAM wParam, LPARAM	lParam);
static BOOL	CALLBACK	MainDlgProc(HWND g_hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

int	APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE	hPrevInstance, LPSTR lpCmdLine,	int	nCmdShow) {
    WSADATA	wsaData;
    INITCOMMONCONTROLSEX initCom;
    g_hInst = hInstance;
    initCom.dwICC = ICC_INTERNET_CLASSES;
    initCom.dwSize = sizeof(INITCOMMONCONTROLSEX);
    InitCommonControlsEx(&initCom);
    if (WSAStartup(MAKEWORD(1, 1), &wsaData)) {
        MessageBox(NULL, "Cannot initialize Winsock DLL\t", "Error", MB_OK | MB_ICONSTOP);
        return 0;
    }
    DialogBox(g_hInst, MAKEINTRESOURCE(IDD_MAINDIALOG),	NULL, (DLGPROC)	MainDlgProc);
    WSACleanup();
    return 1;
}
static BOOL	CALLBACK MainDlgProc(HWND hWndDlg, UINT msg,	WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_INITDIALOG:
        g_hWnd = hWndDlg;
        On_InitDialog();
        return TRUE;
    case WM_CTLCOLORSTATIC:
        if (GetDlgCtrlID((HWND)lParam) == IDC_HOME || GetDlgCtrlID((HWND)lParam) == IDC_MAIL) {
            SetTextColor((HDC)wParam, 0xFF0000);
            SetBkColor((HDC)wParam, GetSysColor(COLOR_MENU));
            return (int)GetStockObject(HOLLOW_BRUSH);
        }
        break;
    case WM_DRAWITEM:
        On_DrawItem(wParam, lParam);
        return TRUE;
    case WM_NOTIFY:
        On_NoTify(wParam, lParam);
        return TRUE;
    case WM_HELP:
        SendMessage(g_hWnd, WM_SYSCOMMAND, IDC_HELPCMD, 0);
        return TRUE;
    case WM_SIZE:
        if (wParam == SIZE_MAXIMIZED || wParam == SIZE_RESTORED) {
            MoveWindow(g_hwndListView, 15, 120, LOWORD(lParam) - 30, HIWORD(lParam) - 155, TRUE);
            MoveWindow(GetDlgItem(g_hWnd, IDG_RESULT), 6, 100, LOWORD(lParam) - 12, HIWORD(lParam) - 125, TRUE);
            SendMessage(g_hwndStatus, WM_SIZE, wParam, lParam);
            ListView_SetColumnWidth(g_hwndListView, 2, LOWORD(lParam) - 280);
        }
        break;
    case WM_SYSCOMMAND:
        if (LOWORD(wParam) == IDC_HELPCMD) {
            if (SearchPath(NULL, "Readme", ".txt", MAX_PATH, strTemp, NULL))
                ShellExecute(g_hWnd, "open", strTemp, NULL, NULL, SW_MAXIMIZE);
        }
        break;
    case WM_COMMAND:
        On_Command(wParam);
        break;
    case WM_CLOSE:
        for (i = 0; i < 6; i++)
            DeleteObject(g_hBitmap[i]);
        if (fpFile = fopen("BrutePortScanner.ini", "w")) {
            SendDlgItemMessage(g_hWnd, IDIP_STARTIP, IPM_GETADDRESS, 0, (LPARAM) &dwStartIP);
            byteIP[0] = (BYTE)FIRST_IPADDRESS(dwStartIP);
            byteIP[1] = (BYTE)SECOND_IPADDRESS(dwStartIP);
            byteIP[2] = (BYTE)THIRD_IPADDRESS(dwStartIP);
            byteIP[3] = (BYTE)FOURTH_IPADDRESS(dwStartIP);
            sprintf(strTemp, "Starting IP Address=%d.%d.%d.%d\n", byteIP[0], byteIP[1], byteIP[2], byteIP[3]);
            fputs(strTemp, fpFile);
            SendDlgItemMessage(g_hWnd, IDIP_ENDIP, IPM_GETADDRESS, 0, (LPARAM) &dwStartIP);
            byteIP[0] = (BYTE)FIRST_IPADDRESS(dwStartIP);
            byteIP[1] = (BYTE)SECOND_IPADDRESS(dwStartIP);
            byteIP[2] = (BYTE)THIRD_IPADDRESS(dwStartIP);
            byteIP[3] = (BYTE)FOURTH_IPADDRESS(dwStartIP);
            sprintf(strTemp, "Ending IP Address=%d.%d.%d.%d\nPort range=%d->%d\nThreads=%d\nDelay=%d\nPort ID=%s\nSaved history records=%s\nUsed ports range=%s\nUsed ports list=%s\nClear without asking=%s\nPort list=",
                    byteIP[0], byteIP[1], byteIP[2], byteIP[3],
                    GetDlgItemInt(g_hWnd, IDE_STARTPORT, NULL, 0), GetDlgItemInt(g_hWnd, IDE_ENDPORT, NULL, 0),
                    GetDlgItemInt(g_hWnd, IDE_THREAD, NULL, 0),
                    GetDlgItemInt(g_hWnd, IDE_TIMEOUT, NULL, 0),
                    ((GetMenuState(g_hMenu, IDC_GETBANNER, MF_BYCOMMAND) & MF_CHECKED)) ? "Yes" : "No",
                    ((GetMenuState(g_hMenu, IDC_KEEPHISTORY, MF_BYCOMMAND) & MF_CHECKED)) ? "Yes" : "No",
                    SendDlgItemMessage(g_hWnd, IDC_USERANGE, BM_GETCHECK, 0, 0) ? "Yes" : "No",
                    SendDlgItemMessage(g_hWnd, IDC_USELIST, BM_GETCHECK, 0, 0) ? "Yes" : "No",
                    isNoAsk ? "Yes" : "No"
                   );
            fputs(strTemp, fpFile);
            GetDlgItemText(g_hWnd, IDE_PORTLIST, strTemp, sizeof(strTemp));
            fputs(strTemp, fpFile);
            fclose(fpFile);
        }
        if (((GetMenuState(g_hMenu, IDC_KEEPHISTORY, MF_BYCOMMAND)	& MF_CHECKED)) )
            SaveResult("PortList.txt", FALSE);
        EndDialog(g_hWnd, 0);
    }
    return FALSE;
}
LRESULT	CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM	lParam) {
    MSG	msg;
    if (nCode >= 0 &&	(IsChild(g_hWnd, ((MOUSEHOOKSTRUCT *)lParam)->hwnd))) {
        if (wParam == WM_MOUSEMOVE ||	wParam == WM_LBUTTONDOWN || wParam == WM_RBUTTONDOWN) {
            msg.lParam = 0;
            msg.wParam = 0;
            msg.message	= wParam;
            msg.hwnd = ((MOUSEHOOKSTRUCT *)lParam)->hwnd;
            SendMessage(g_hwndToolTip, TTM_RELAYEVENT, 0, (LPARAM) (LPMSG) &msg);
        }
    }
    return (CallNextHookEx(g_hHook,	nCode, wParam, lParam));
}
LRESULT CALLBACK HyperLinkProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_LBUTTONUP:
        switch (GetDlgCtrlID(hwnd)) {
        case IDC_HOME:
            ShellExecute(g_hWnd, "open", c_szToolTip[12], NULL, NULL, SW_MAXIMIZE);
            break;
        case IDC_MAIL:
            ShellExecute(g_hWnd, "open", c_szToolTip[13], NULL, NULL, SW_MAXIMIZE);
        }
        break;
    case WM_NCHITTEST:
    case WM_SETCURSOR:
        SetCursor(g_hCursor);
        break;
    default:
        return CallWindowProc((WNDPROC)GetWindowLong(hwnd, GWL_USERDATA), hwnd, uMsg, wParam, lParam);
    }
    return TRUE;
}
static int CALLBACK	CompareFunc(LPARAM lParam1,	LPARAM lParam2,	LPARAM lParamSort) {
#define	pItem1 ((ITEMINFO *) lParam1)
#define	pItem2 ((ITEMINFO *) lParam2)
    if (!lParamSort) {
        if (	(pItem1->dwAddr) ==	(pItem2->dwAddr) ) {
            if (	(pItem1->wPort)	== (pItem2->wPort) )
                return 0;
            else if ( (pItem1->wPort) > (pItem2->wPort) )
                return 1;
            else
                return -1;
        } else if ( (pItem1->dwAddr) >	(pItem2->dwAddr) )
            return 1;
        else
            return -1;
    } else if (lParamSort == 1) {
        if (	(pItem1->wPort)	== (pItem2->wPort) ) {
            if (	(pItem1->dwAddr) ==	(pItem2->dwAddr) )
                return 0;
            else if ( (pItem1->dwAddr) >	(pItem2->dwAddr) )
                return 1;
            else
                return -1;
        } else if ( (pItem1->wPort) > (pItem2->wPort) )
            return 1;
        else
            return -1;
    } else
        return (	lstrcmpi(pItem1->lpstrBanner, pItem2->lpstrBanner) );
#undef pItem1
#undef pItem2
}
void WINAPI	On_InitDialog() {
    TOOLINFO ti;
    HICON hIcon;
    LV_COLUMN lvc;
    long sbParts[4];
    HIMAGELIST hImageList;
    g_hCursor = LoadCursor(g_hInst, MAKEINTRESOURCE(IDC_CURSOR_HAND));
    g_hMenu	= GetSystemMenu(g_hWnd, FALSE);
    AppendMenu(g_hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(g_hMenu, MF_ENABLED, IDC_HELPCMD, "Help(&H)\tF1");
    g_hMenu = GetSubMenu(LoadMenu(g_hInst, MAKEINTRESOURCE(IDM_MENU)), 0);
    g_hBitmap[0] = LoadBitmap(g_hInst, MAKEINTRESOURCE(IDB_CHECK));
    g_hBitmap[1] = LoadBitmap(g_hInst, MAKEINTRESOURCE(IDB_UNCHECK));
    SetMenuItemBitmaps(g_hMenu,	IDC_GETBANNER, MF_BYCOMMAND, g_hBitmap[1], g_hBitmap[0]);
    SetMenuItemBitmaps(g_hMenu,	IDC_KEEPHISTORY, MF_BYCOMMAND, g_hBitmap[1], g_hBitmap[0]);
    for (i = 0; i < 6; i++)
        g_hBitmap[i] = LoadBitmap(g_hInst, MAKEINTRESOURCE( (i % 3) + 200	) );
    CreateUpDownControl(WS_CHILD | WS_BORDER | WS_VISIBLE | UDS_SETBUDDYINT | UDS_ALIGNRIGHT, 0, 0, 0, 0, g_hWnd, 0, g_hInst, GetDlgItem(g_hWnd, IDE_TIMEOUT), 20, 1, 2);
    sbParts[0] = 241;
    sbParts[1] = 355;
    sbParts[2] = 455;
    sbParts[3] = -1;
    g_hwndStatus = CreateStatusWindow(WS_CHILD | WS_VISIBLE, c_szWelcome, g_hWnd, IDS_STATUS);
    SendMessage(g_hwndStatus, SB_SETPARTS, (WPARAM) 4, (LPARAM) sbParts);
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)1, (LPARAM)"Ready");
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)2, (LPARAM)"Active thread:0");
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)3, (LPARAM)"Opened port:0");
    g_hwndToolTip =	CreateWindowEx(0, TOOLTIPS_CLASS, (LPSTR) NULL,	TTS_ALWAYSTIP, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,	CW_USEDEFAULT, g_hWnd, (HMENU) NULL, g_hInst, NULL);
    ti.cbSize =	sizeof(TOOLINFO);
    ti.uFlags =	TTF_IDISHWND;
    ti.hwnd	= g_hWnd;
    ti.hinst = 0;
    ti.lpszText	= LPSTR_TEXTCALLBACK;
    for (i = IDIP_STARTIP; i <= IDC_MAIL; i++) {
        ti.uId = (UINT)	GetDlgItem(g_hWnd, i);
        SendMessage(g_hwndToolTip, TTM_ADDTOOL,	0, (LPARAM)	(LPTOOLINFO) &ti);
    }
    g_hHook	= SetWindowsHookEx(WH_MOUSE, MouseProc, (HINSTANCE) NULL, GetCurrentThreadId());
    hImageList =	ImageList_Create(16, 16,	ILC_COLOR8,	1, 1);
    for (i = 300; i < 312; i++) {
        hIcon = LoadIcon(g_hInst,	MAKEINTRESOURCE(i));
        if (i == 300)
            SetClassLong(g_hWnd, GCL_HICON, (LONG)hIcon);
        ImageList_AddIcon(hImageList, hIcon);
        DeleteObject(hIcon);
    }
    g_hwndListView = GetDlgItem(g_hWnd, IDL_RESULT);
    ListView_SetExtendedListViewStyle(g_hwndListView, LVS_EX_GRIDLINES | LVS_EX_SUBITEMIMAGES);
    ListView_SetImageList(g_hwndListView, hImageList, LVSIL_SMALL);
    lvc.mask = LVCF_WIDTH |	LVCF_TEXT |	LVCF_SUBITEM ;
    lvc.cx = 150;
    lvc.iSubItem = 0;
    lvc.pszText = "IP Address";
    ListView_InsertColumn(g_hwndListView, 0, &lvc);
    lvc.cx = 75;
    lvc.iSubItem = 1;
    lvc.pszText = "Port";
    ListView_InsertColumn(g_hwndListView, 1, &lvc);
    lvc.cx = 280;
    lvc.iSubItem = 2;
    lvc.pszText = "ID";
    ListView_InsertColumn(g_hwndListView, 2, &lvc);
    SendDlgItemMessage(g_hWnd, IDE_STARTPORT, EM_SETLIMITTEXT, (WPARAM) 5, 0);
    SendDlgItemMessage(g_hWnd, IDE_ENDPORT, EM_SETLIMITTEXT, (WPARAM) 5, 0);
    SendDlgItemMessage(g_hWnd, IDE_PORTLIST, EM_SETLIMITTEXT, (WPARAM)	600, 0);
    SendDlgItemMessage(g_hWnd, IDE_THREAD, EM_SETLIMITTEXT, (WPARAM) 10, 0);
    SendDlgItemMessage(g_hWnd, IDE_TIMEOUT, EM_SETLIMITTEXT, (WPARAM) 2, 0);
    SendDlgItemMessage(g_hWnd, IDC_USELIST, BM_SETCHECK, 1, 0);
    SetWindowLong(GetDlgItem(g_hWnd, IDC_HOME), GWL_USERDATA, (LONG)SetWindowLong(GetDlgItem(g_hWnd, IDC_HOME), GWL_WNDPROC, (LONG)HyperLinkProc));
    SetWindowLong(GetDlgItem(g_hWnd, IDC_MAIL), GWL_USERDATA, (LONG)SetWindowLong(GetDlgItem(g_hWnd, IDC_MAIL), GWL_WNDPROC, (LONG)HyperLinkProc));
    if (fpFile = fopen("BrutePortScanner.ini", "r")) {
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            for (i = 0; i < 4; i++) {
                byteIP[i] = atoi(p);
                for (; *p;)
                    if (*(p++) == '.')
                        break;
            }
            if (byteIP[0] || byteIP[1] || byteIP[2] || byteIP[3])
                SendDlgItemMessage(g_hWnd, IDIP_STARTIP, IPM_SETADDRESS, 0, (LPARAM) MAKEIPADDRESS(byteIP[0], byteIP[1], byteIP[2], byteIP[3]));
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            for (i = 0; i < 4; i++) {
                byteIP[i] = atoi(p);
                for (; *p;)
                    if (*(p++) == '.')
                        break;
            }
            if (byteIP[0] || byteIP[1] || byteIP[2] || byteIP[3])
                SendDlgItemMessage(g_hWnd, IDIP_ENDIP, IPM_SETADDRESS, 0, (LPARAM) MAKEIPADDRESS(byteIP[0], byteIP[1], byteIP[2], byteIP[3]));
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            if (atoi(p))
                SetDlgItemInt(g_hWnd, IDE_STARTPORT, atoi(p), 0);
            for (; *p;)
                if (*(p++) == '>')
                    break;
            if (atoi(p))
                SetDlgItemInt(g_hWnd, IDE_ENDPORT, atoi(p), 0);
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            SetDlgItemInt(g_hWnd, IDE_THREAD, atoi(p), 0);
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            SetDlgItemInt(g_hWnd, IDE_TIMEOUT, atoi(p), 0);
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            if (*p == 'Y' || *p == 'y')
                CheckMenuItem(g_hMenu, IDC_GETBANNER, MF_CHECKED);
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            if ((*p == 'N' || *p == 'n'))
                CheckMenuItem(g_hMenu, IDC_KEEPHISTORY, MF_UNCHECKED);
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            SendDlgItemMessage(g_hWnd, IDC_USERANGE, BM_SETCHECK, *p == 'Y' || *p == 'y', 0);
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            if ( (*p == 'N' || *p == 'n') && SendDlgItemMessage(g_hWnd, IDC_USERANGE, BM_GETCHECK, 0, 0) )
                SendDlgItemMessage(g_hWnd, IDC_USELIST, BM_SETCHECK, 0, 0);
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        if (p = strchr(strTemp, '=')) {
            p++;
            if (*p == 'Y' || *p == 'y')
                isNoAsk = TRUE;
        }
        fgets(strTemp, sizeof(strTemp), fpFile);
        p = strrchr(strTemp, '\n');
        if (p)
            *p = 0;
        if (p = strchr(strTemp, '=')) {
            p++;
            SetDlgItemText(g_hWnd, IDE_PORTLIST, p);
        }
        fclose(fpFile);
    }
    if (GetMenuState(g_hMenu, IDC_KEEPHISTORY, MF_BYCOMMAND) &	MF_CHECKED)
        LoadResult("PortList.txt");
}
void WINAPI	On_Command(WPARAM wParam) {
    char *pTemp;
    OPENFILENAME ofn;
    switch (LOWORD(wParam)) {
    case IDIP_STARTIP:
        if ((HIWORD(wParam)) == EN_CHANGE) {
            if (SendDlgItemMessage(g_hWnd, IDIP_STARTIP, IPM_ISBLANK, 0, 0))
                SendDlgItemMessage(g_hWnd, IDIP_ENDIP, IPM_CLEARADDRESS, 0, 0);
            else {
                SendDlgItemMessage(g_hWnd, IDIP_STARTIP, IPM_GETADDRESS, 0, (LPARAM) &dwStartIP);
                byteIP[0] = (BYTE)FIRST_IPADDRESS(dwStartIP);
                byteIP[1] = (BYTE)SECOND_IPADDRESS(dwStartIP);
                byteIP[2] = (BYTE)THIRD_IPADDRESS(dwStartIP);
                byteIP[3] = (BYTE)FOURTH_IPADDRESS(dwStartIP);
                SendDlgItemMessage(g_hWnd, IDIP_ENDIP, IPM_SETADDRESS, 0, (LPARAM) MAKEIPADDRESS(byteIP[0], (byteIP[1] || byteIP[2] || byteIP[3]) ? byteIP[1] : 255, (byteIP[2] || byteIP[3]) ? byteIP[2] : 255, (byteIP[3] == 0 || byteIP[3] == 1) ? 255 : byteIP[3]));
            }
        }
        break;
    case IDE_STARTPORT:
    case IDE_ENDPORT:
        if ((HIWORD(wParam)) == EN_CHANGE) {
            i = GetDlgItemInt(g_hWnd, LOWORD(wParam), NULL, FALSE);
            if (i > 65535)
                SetDlgItemInt(g_hWnd, LOWORD(wParam), 65535, 0);
            else if ( i && (LOWORD(wParam) == IDE_STARTPORT) )
                SetDlgItemInt(g_hWnd, IDE_ENDPORT, i, 0);
        }
        break;
    case IDE_PORTLIST:
        if ((HIWORD(wParam)) == EN_CHANGE) {
            pTemp = NULL;
            GetDlgItemText(g_hWnd, IDE_PORTLIST, strTemp, sizeof(strTemp));
            for (p = strTemp; *p;) {
                if ((*p < 48 || *p > 57) && (*p != ',')	&& (*p != ';') &&	(*p != ' ') && (*p != '.'))
                    for (pTemp = p; *pTemp; pTemp++)
                        *pTemp = *(pTemp + 1);
                else
                    p++;
            }
            if (pTemp)
                SetDlgItemText(g_hWnd, IDE_PORTLIST, strTemp);
        }
        break;
    case IDE_THREAD:
    case IDE_TIMEOUT:
        if (	((HIWORD(wParam)) == EN_CHANGE) && (GetDlgItemInt(g_hWnd, LOWORD(wParam), NULL, FALSE) >	(LOWORD(wParam) == IDE_THREAD	? (UINT)2000	: (UINT)20)	) )
            SetDlgItemInt(g_hWnd, LOWORD(wParam), LOWORD(wParam) == IDE_THREAD ? 2000 : 20, FALSE);
        break;
    case IDC_USERANGE:
    case IDC_USELIST:
        if (SendDlgItemMessage(g_hWnd, LOWORD(wParam), BM_GETCHECK, 0, 0)) {
            SendDlgItemMessage(g_hWnd, LOWORD(wParam), BM_SETCHECK, 0, 0);
            if (!SendDlgItemMessage(g_hWnd, (LOWORD(wParam) == IDC_USELIST) ? IDC_USERANGE : IDC_USELIST, BM_GETCHECK, 0, 0))
                SendDlgItemMessage(g_hWnd, (LOWORD(wParam) == IDC_USELIST) ? IDC_USERANGE : IDC_USELIST, BM_SETCHECK, 1, 0);
        } else
            SendDlgItemMessage(g_hWnd, LOWORD(wParam), BM_SETCHECK, 1, 0);
        break;
    case IDC_GETBANNER:
    case IDC_KEEPHISTORY:
        if (CheckMenuItem(g_hMenu, LOWORD(wParam), MF_CHECKED) == MF_CHECKED)
            CheckMenuItem(g_hMenu, LOWORD(wParam), MF_UNCHECKED);
        TrackPopupMenu(g_hMenu, 0, ptCur.x, ptCur.y, 0, g_hWnd, NULL);
        break;
    case IDC_SCAN:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)StartScan, 0, 0, &dwThreadID);
        break;
    case IDC_STOP:
        isStopForce = TRUE;
        break;
    case IDC_LOAD:
    case IDC_SAVE:
        ZeroMemory(&ofn, sizeof(ofn));
        ofn.lStructSize	= sizeof(ofn);
        ofn.hInstance =	g_hInst;
        ofn.hwndOwner =	g_hWnd;
        ofn.lpstrFile =	"PortList.txt";
        ofn.nMaxFile = 256;
        ofn.lpstrFilter	= "Pure text files\0*.txt\0All files\0*.*\0";
        ofn.lpstrDefExt	= "txt";
        if (LOWORD(wParam) == IDC_LOAD) {
            ofn.lpstrTitle = "Import result file";
            ofn.Flags =	527372 | OFN_FILEMUSTEXIST;
            if (GetOpenFileName(&ofn))
                SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, LoadResult(ofn.lpstrFile)	? (LPARAM)"Succeeded!" : (LPARAM)"Failed!");
        } else {
            ofn.lpstrTitle = (ListView_GetSelectedCount(g_hwndListView)) ? "Save selected results as..." :	"Save all results as...";
            ofn.Flags =	527372 | OFN_OVERWRITEPROMPT;
            if (GetSaveFileName(&ofn))
                SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (SaveResult(ofn.lpstrFile, ListView_GetSelectedCount(g_hwndListView)))	? (LPARAM)"文件保存成功" : (LPARAM)"文件保存失败");
        }
        break;
    case IDC_DEL:
        if (ListView_GetSelectedCount(g_hwndListView)) {
            for (i = 0; i < nItemCount;) {
                if (ListView_GetItemState(g_hwndListView, i, LVIS_SELECTED)) {
                    ListView_DeleteItem(g_hwndListView, i);
                    nItemCount--;
                    nScannedPort = i;
                } else
                    i++;
            }
            ListView_SetItemState(g_hwndListView, nScannedPort - ((nScannedPort == i) ? 1 : 0), LVIS_SELECTED, LVIS_SELECTED);
            ListView_EnsureVisible(g_hwndListView, nScannedPort - ((nScannedPort == i) ? 1 : 0), TRUE);
        } else {
            if (isNoAsk || (HIBYTE(GetKeyState(VK_CONTROL))) || (MessageBox(g_hWnd, "Sure to clear all the results that contain port scan history?", "Yes", MB_OKCANCEL | MB_ICONQUESTION) == IDOK)	) {
                ListView_DeleteAllItems(g_hwndListView);
                nItemCount = 0;
            }
        }
        sprintf(strTemp, "Opened port:%d", nItemCount);
        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)3, (LPARAM)strTemp);
        break;
    case IDC_SELECTALL:
        for (i = 0; i < nItemCount; i++) {
            ListView_SetItemState(g_hwndListView, i, LVIS_SELECTED, LVIS_SELECTED);
            if (isUseResultIP)
                ListView_SetItemState(g_hwndListView, i, INDEXTOSTATEIMAGEMASK(2), LVIS_STATEIMAGEMASK);
        }
        break;
    case IDC_SELECTINVERSE:
        for (i = 0; i < nItemCount; i++) {
            if (ListView_GetItemState(g_hwndListView, i, LVIS_SELECTED)) {
                ListView_SetItemState(g_hwndListView, i, 0, LVIS_SELECTED);
                if (isUseResultIP)
                    ListView_SetItemState(g_hwndListView, i, INDEXTOSTATEIMAGEMASK(1), LVIS_STATEIMAGEMASK);
            } else {
                ListView_SetItemState(g_hwndListView, i, LVIS_SELECTED, LVIS_SELECTED);
                if (isUseResultIP)
                    ListView_SetItemState(g_hwndListView, i, INDEXTOSTATEIMAGEMASK(2), LVIS_STATEIMAGEMASK);
            }
        }
        break;
    case IDC_CUT:
    case IDC_COPY:
        if (OpenClipboard(g_hWnd)) {
            EmptyClipboard();
            if (p = GlobalAlloc(GMEM_DDESHARE, ListView_GetSelectedCount(g_hwndListView) * 18)) {
                GlobalLock(p);
                *p = '\0';
                for (i = 0; i < nItemCount; i++) {
                    if (ListView_GetItemState(g_hwndListView, i, LVIS_SELECTED)) {
                        ListView_GetItemText(g_hwndListView, i, 0, strTemp, sizeof(strTemp));
                        strcat(p, strTemp);
                        strcat(p, "\r\n");
                    }
                }
                if (pTemp = strrchr(p, '\r'))
                    * pTemp = '\0';
                GlobalUnlock(p);
                if (SetClipboardData(CF_TEXT, p)) {
                    CloseClipboard();
                    if (LOWORD(wParam) == IDC_CUT) {
                        SendMessage(g_hWnd, WM_COMMAND, IDC_DEL, 0);
                        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM)"Already copied the selected address to the clipboard");
                    } else
                        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM)"Already copied the selected address to the clipboard");
                    break;
                }
            }
        }
        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM)"Failed to copy the selected address to the clipboard");
        break;
    case IDC_SORTIP:
    case IDC_SORTPORT:
    case IDC_SORTBANNER:
        ListView_SortItems(	g_hwndListView,	CompareFunc, LOWORD(wParam) - 514 );
        break;
    case IDC_TELNET:
        for (i = 0; i < nItemCount; i++) {
            if (ListView_GetItemState(g_hwndListView, i, LVIS_SELECTED)) {
                ListView_GetItemText(g_hwndListView, i, 0, strTemp, sizeof(strTemp));
                p = strTemp + strlen(strTemp);
                *(p++) = ' ';
                ListView_GetItemText(g_hwndListView, i, 1, p, 6);
                ShellExecute(g_hWnd, "open", "telnet.exe", strTemp, NULL, SW_SHOWNORMAL);
            }
        }
        break;
    case IDC_RESOLVEDOMAIN:
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ResolveDomain, 0, 0, &dwThreadID);
        break;
    }
}
void WINAPI	On_NoTify(WPARAM wParam, LPARAM lParam) {
#define lpmsg ((LPNMHDR)lParam)
    switch (lpmsg->code) {
    case TTN_NEEDTEXT:
        ((LPTOOLTIPTEXT) lParam)->lpszText = (LPSTR) c_szToolTip[GetDlgCtrlID((HWND) lpmsg->idFrom) - 400];
        break;
    case TTN_SHOW:
        SendMessage(g_hwndStatus, SB_SETTEXT, 0, (LONG) c_szToolTip[GetDlgCtrlID((HWND) lpmsg->idFrom) - 400]);
        break;
    case TTN_POP:
        SendMessage(g_hwndStatus, SB_SETTEXT, 0, (LONG)c_szWelcome);
        break;
    case LVN_COLUMNCLICK:
#define	pnm	((NM_LISTVIEW *) lParam)
        ListView_SetColumnWidth(g_hwndListView, 0, 150);
        ListView_SetColumnWidth(g_hwndListView, 1, 75);
        ListView_SortItems(	g_hwndListView,	CompareFunc, (LPARAM) (pnm->iSubItem) );
#undef pnm
        break;
    case LVN_GETDISPINFO:
#define	pnmv ((LV_DISPINFO *) lParam)
        if (pnmv->item.mask	& LVIF_TEXT) {
#define	pItem ((ITEMINFO *)(pnmv->item.lParam))
            if (	!(pnmv->item.iSubItem) ) {
                iaServer.s_addr = htonl(pItem->dwAddr);
                lstrcpy(pnmv->item.pszText,	inet_ntoa(iaServer));
            } else if ( pnmv->item.iSubItem ==	1 ) {
                char strString[6];
                sprintf(strString, "%d", pItem->wPort);
                lstrcpy(pnmv->item.pszText, strString);
            } else
                lstrcpy(pnmv->item.pszText,	pItem->lpstrBanner);
#undef pItem
        }
#undef pnmv
        break;
    case NM_RCLICK:
        i = ListView_GetSelectedCount(g_hwndListView);
        EnableMenuItem(g_hMenu, IDC_COPY, i ? MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_CUT, (i && !nThreadNum)	? MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_SELECTINVERSE, i ? MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_RESOLVEDOMAIN, (i	&& !nThreadNum) ?	MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_TELNET, i ? MF_ENABLED : MF_GRAYED);
        ModifyMenu(g_hMenu, IDC_DEL, MF_BYCOMMAND, IDC_DEL, i ? "DELETE\tDel" : "DELETE\tCtrl+Del");
        EnableMenuItem(g_hMenu, IDC_SORTIP, nItemCount ?  MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_SORTPORT, nItemCount ? MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_SORTBANNER, nItemCount ? MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_DEL, (nItemCount &&	!nThreadNum) ? MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_SELECTALL, nItemCount ? MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_SAVE, nItemCount ? MF_ENABLED : MF_GRAYED);
        EnableMenuItem(g_hMenu, IDC_LOAD, nThreadNum ? MF_GRAYED : MF_ENABLED);
        GetCursorPos(&ptCur);
        TrackPopupMenu(g_hMenu, 0, ptCur.x, ptCur.y, 0, g_hWnd, NULL);
        break;
    case LVN_KEYDOWN:
        i = ListView_GetSelectedCount(g_hwndListView);
#define	pnm	((LV_KEYDOWN *)	lParam)
        switch (pnm->wVKey) {
        case 46:
            if (!nThreadNum) {
                if (HIBYTE(GetKeyState(VK_CONTROL))) {
                    ListView_DeleteAllItems(g_hwndListView);
                    nItemCount = 0;
                    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)3, (LPARAM)"Opened port:0");
                } else if (nItemCount)
                    SendMessage(g_hWnd, WM_COMMAND, IDC_DEL, 0);
            }
            break;
        case 65:
            if (nItemCount	&& HIBYTE(GetKeyState(VK_CONTROL)) )
                SendMessage(g_hWnd, WM_COMMAND, IDC_SELECTALL, 0);
            break;
        case 67:
            if (i &&	HIBYTE(GetKeyState(VK_CONTROL)))
                SendMessage(g_hWnd, WM_COMMAND, IDC_COPY, 0);
            break;
        case 68:
            isUseResultIP =	!isUseResultIP;
            ListView_SetExtendedListViewStyle(g_hwndListView, isUseResultIP ? (LVS_EX_GRIDLINES | LVS_EX_SUBITEMIMAGES | LVS_EX_CHECKBOXES) : (LVS_EX_GRIDLINES | LVS_EX_SUBITEMIMAGES) );
            SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, isUseResultIP	? (LPARAM)"Please select the address of the result window to scan":(LPARAM)"To activate the hidden function, press Ctrl+D in the result window");
            break;
        case 73:
            if (i &&	HIBYTE(GetKeyState(VK_CONTROL)))
                SendMessage(g_hWnd, WM_COMMAND, IDC_SELECTINVERSE, 0);
            break;
        case 88:
            if (i &&	(!nThreadNum)	&& HIBYTE(GetKeyState(VK_CONTROL)))
                SendMessage(g_hWnd, WM_COMMAND, IDC_CUT, 0);
            break;
        }
#undef pnm
    }
#undef lpmsg
}
void WINAPI	On_DrawItem(WPARAM wParam, LPARAM lParam) {
    HDC	hdcMem;
    hdcMem = CreateCompatibleDC(((LPDRAWITEMSTRUCT)	lParam)->hDC);
    SetBkMode(hdcMem, TRANSPARENT);
    SelectObject(hdcMem, GetStockObject(DEFAULT_GUI_FONT));
    i =	((LPDRAWITEMSTRUCT)	lParam)->itemState & ODS_SELECTED;
    if (wParam == IDC_SCAN) {
        if (	( (LPDRAWITEMSTRUCT) lParam)->itemState	& ODS_DISABLED )
            SelectObject(hdcMem, g_hBitmap[2]);
        else
            SelectObject(hdcMem, g_hBitmap[i]);
        TextOut(hdcMem, 12 + i, 5 + i, "Scan", 5);
    } else if (wParam == IDC_STOP) {
        if (	( (LPDRAWITEMSTRUCT) lParam)->itemState	& ODS_DISABLED )
            SelectObject(hdcMem, g_hBitmap[5]);
        else
            SelectObject(hdcMem, g_hBitmap[i + 3]);
        TextOut(hdcMem, 12 + i, 5 + i, "Stop", 5);
    }
    BitBlt(((LPDRAWITEMSTRUCT) lParam)->hDC, ((LPDRAWITEMSTRUCT)	lParam)->rcItem.left, ((LPDRAWITEMSTRUCT) lParam)->rcItem.top, ((LPDRAWITEMSTRUCT) lParam)->rcItem.right - ((LPDRAWITEMSTRUCT) lParam)->rcItem.left, ((LPDRAWITEMSTRUCT) lParam)->rcItem.bottom -	((LPDRAWITEMSTRUCT)	lParam)->rcItem.top, hdcMem, 0,	0, SRCCOPY);
    DeleteDC(hdcMem);
}
void WINAPI	StartScan() {
    int k = 0;
    int j;
    int intINT;
    int intMAXThread;
    char *pPoint1;
    char *pPoint2;
    char strString[600];
    IN_ADDR iaServer;
    DWORD dwStartTime, dwCurIP;
    BOOL isStartScanRange = TRUE;
    nSkipHost = 0;
    nPortCount = 0;
    nScannedPort		= 0;
    isStopForce = FALSE;
    ZeroMemory(&thdINFO, 300 * sizeof(THREADINFO));
    isGetBanner = (GetMenuState(g_hMenu, IDC_GETBANNER, MF_BYCOMMAND) &	MF_CHECKED);
    isKeepHistroy = (GetMenuState(g_hMenu, IDC_KEEPHISTORY, MF_BYCOMMAND) &	MF_CHECKED);
    isUsePortRange = SendDlgItemMessage(g_hWnd, IDC_USERANGE, BM_GETCHECK, 0, 0);
    isUsePortList = SendDlgItemMessage(g_hWnd, IDC_USELIST, BM_GETCHECK, 0, 0); 
    intMAXThread = GetDlgItemInt(g_hWnd, IDE_THREAD, NULL, 0);
    if (!intMAXThread) {
        SetDlgItemInt(g_hWnd, IDE_THREAD, 50, 0);
        intMAXThread = 50;
    }
    nTimeOut = GetDlgItemInt(g_hWnd, IDE_TIMEOUT, NULL, 0);
    if (!nTimeOut) {
        SetDlgItemInt(g_hWnd, IDE_TIMEOUT, 3, 0);
        nTimeOut = 3;
    }
    SendDlgItemMessage(g_hWnd, IDIP_STARTIP, IPM_GETADDRESS, 0, (LPARAM) &dwStartIP);
    SendDlgItemMessage(g_hWnd, IDIP_ENDIP, IPM_GETADDRESS, 0, (LPARAM) &dwEndIP);
    if (dwStartIP > dwEndIP) {
        dwCurIP = dwStartIP;
        dwStartIP = dwEndIP;
        dwEndIP = dwCurIP;
        SendDlgItemMessage(g_hWnd, IDIP_STARTIP, IPM_SETADDRESS, 0, dwStartIP);
        SendDlgItemMessage(g_hWnd, IDIP_ENDIP, IPM_SETADDRESS, 0, dwEndIP);
    }
    if (isUsePortRange) {
        nStartPort = GetDlgItemInt(g_hWnd, IDE_STARTPORT, NULL, 0);
        nEndPort = GetDlgItemInt(g_hWnd, IDE_ENDPORT, NULL, 0);
        if (nStartPort > nEndPort) {
            intINT = nStartPort;
            nStartPort = nEndPort;
            nEndPort = intINT;
        }
        if (!nStartPort) {
            if (!nEndPort)
                isUsePortRange = FALSE;
            else {
                nStartPort = nEndPort;
                SetDlgItemInt(g_hWnd, IDE_STARTPORT, nEndPort, 0);
                SetDlgItemInt(g_hWnd, IDE_ENDPORT, nEndPort, 0);
            }
        }
    }
    if (isUsePortList) {
        GetDlgItemText(g_hWnd, IDE_PORTLIST, strString, 599);
        pPoint1 = strString;
        for (nPortCount = 0; *pPoint1	&& (nPortCount < 100);) {
            j = atoi(pPoint1);
            if (j &&	j < 65535	&& (j < nStartPort || j > nEndPort || !isUsePortRange )) {
                nPort[nPortCount] = j;
                nPortCount++;
            }
            if (!( (pPoint2 = strchr(pPoint1, ','))	|| (pPoint2 = strchr(pPoint1, ';')) ||	(pPoint2 = strchr(pPoint1, ' ')) || (pPoint2 = strchr(pPoint1, '.')) ))
                break;
            pPoint1 = ++pPoint2;
        }
        if (!nPortCount)
            isUsePortList = FALSE;
    }
    if (isUsePortList || isUsePortRange) {
        EnableWindow(GetDlgItem(g_hWnd, IDC_SCAN), 0);
        EnableWindow(GetDlgItem(g_hWnd, IDC_STOP), 1);
        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)1, (LPARAM)"Completed percentage:0%");
        if (isUsePortList)
            j = nPort[0];
        else
            j = nStartPort;
        if (isUseResultIP) {
            dwCurIP = 0;
            for	(dwStartIP = 0, dwEndIP = 0; (int)dwEndIP	< nItemCount; dwEndIP++)
                if (ListView_GetCheckState(g_hwndListView, dwEndIP))
                    dwStartIP++;
        } else {
            dwCurIP = dwStartIP;
            if (!isKeepHistroy) {
                ListView_DeleteAllItems(g_hwndListView);
                nItemCount = 0;
                sprintf(strTemp, "Opened port:%d", nItemCount);
                SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)3, (LPARAM)strTemp);
            }
        }
        dwStartTime = GetTickCount();
        while (dwCurIP <= dwEndIP) {
            if (isStopForce)
                break;
            if (	((dwCurIP %	256) == 0	|| (dwCurIP	% 256) == 255) &&	!isUseResultIP) {
                nSkipHost++;
                dwCurIP++;
                continue;
            }
            if (nThreadNum < intMAXThread) {
                for (intINT = 0; intINT < intMAXThread; intINT++)
                    if (thdINFO[intINT].wPort == 0)
                        break;
                if (isUseResultIP) {
                    while (dwCurIP < dwEndIP) {
                        if (ListView_GetCheckState(g_hwndListView, dwCurIP))
                            break;
                        dwCurIP++;
                    }
                    if (dwCurIP == dwEndIP)
                        break;
                    ListView_GetItemText(g_hwndListView, dwCurIP, 0, strTemp, 16);
                    thdINFO[intINT].dwAddr = htonl(inet_addr(strTemp));
                } else
                    thdINFO[intINT].dwAddr = dwCurIP;
                thdINFO[intINT].wPort = j;
                CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ScanThread, (LPVOID)intINT, 0, &dwThreadID);
                nThreadNum++;
                iaServer.s_addr = htonl(thdINFO[intINT].dwAddr);
                sprintf(strString, "Scanning %s:%d", inet_ntoa(iaServer), j);
                SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM)strString);
                sprintf(strString, "Active thread:%d", nThreadNum);
                SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)2, (LPARAM)strString);
                if (isUsePortRange) {
                    if (isUsePortList) { 
                        if (k == nPortCount - 1) {
                            if (isStartScanRange) {
                                j = nStartPort;
                                isStartScanRange = FALSE;
                            } else {
                                if (j == nEndPort) {
                                    j = nPort[0];
                                    k = 0;
                                    isStartScanRange = TRUE;
                                    dwCurIP++;
                                } else
                                    j++;
                            }
                        } else {
                            k++;
                            j = nPort[k];
                        }
                    } else { 
                        if (j == nEndPort) {
                            j = nStartPort;
                            dwCurIP++;
                        } else
                            j++;
                    }
                } else { 
                    if (k == nPortCount - 1) {
                        k = 0;
                        dwCurIP++;
                    } else
                        k++;
                    j = nPort[k];
                }
            }
        }
        if (isStopForce) {
            SendDlgItemMessage(g_hWnd, IDIP_STARTIP, IPM_SETADDRESS, 0, dwCurIP);
            SendDlgItemMessage(g_hWnd, IDIP_ENDIP, IPM_SETADDRESS, 0, dwEndIP);
        }
        for (dwCurIP = 0, j = 1; nThreadNum;) {
            if (!(dwCurIP % 500000)) {
                if (isStopForce) {
                    EnableWindow(GetDlgItem(g_hWnd, IDC_STOP), 0);
                    strcpy(strString, "Scan aborted, waiting for thread to exit");
                } else
                    strcpy(strString, "All threads are created and wait for exit");
                for (intINT = 0; intINT	< (int)((dwCurIP / 500000) % 7); intINT++)
                    strcat(strString, ">");
                SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM)strString);
                if (dwCurIP == 3000000)
                    j = 0;
                else if (dwCurIP == 0)
                    j = 1;
            }
            if (j)
                dwCurIP++;
            else
                dwCurIP--;
        }
        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, isStopForce ? (LPARAM)"Aborted" : (LPARAM)"Completed");
        sprintf(strString, "Cost %dms", GetTickCount() - dwStartTime);
        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)1, (LPARAM)strString);
        EnableWindow(GetDlgItem(g_hWnd, IDC_SCAN), 1);
        EnableWindow(GetDlgItem(g_hWnd, IDC_STOP), 0);
    } else {
        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM)"No ports to scan");
        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)1, (LPARAM)"Ready");
    }
}
void WINAPI	ScanThread(int intTread) {
    LV_ITEM lvi;
    FD_SET mask;
    u_long value;
    SOCKET sockfd;
    TIMEVAL timeout;
    SOCKADDR_IN addr;
    int intCurThread		= intTread;
    int intINT;
    char strString[600];
    char *pPoint1;
    char *pPoint2;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == INVALID_SOCKET)
        SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM)"Cannot create Socket");
    else {
        value = 1;
        ioctlsocket(sockfd, FIONBIO, &value);
        addr.sin_family	= AF_INET;
        addr.sin_port =	htons(thdINFO[intCurThread].wPort);
        addr.sin_addr.s_addr = ntohl(thdINFO[intCurThread].dwAddr);
        connect(sockfd, (struct sockaddr *) &addr, sizeof(addr));
        timeout.tv_sec = nTimeOut;
        timeout.tv_usec = 0;
        FD_ZERO(&mask);
        FD_SET(sockfd, &mask);
        value = select(sockfd + 1, NULL, &mask, NULL, &timeout);
        if (value &&	value != SOCKET_ERROR) {
            ITEMINFO *pItem	= LocalAlloc(LPTR, sizeof(ITEMINFO));
            pItem->dwAddr = thdINFO[intCurThread].dwAddr;
            pItem->wPort = thdINFO[intCurThread].wPort;
            pItem->lpstrBanner = NULL;
            nItemCount++;
            lvi.mask = LVIF_TEXT | LVIF_IMAGE |	LVIF_PARAM;
            lvi.pszText	= LPSTR_TEXTCALLBACK;
            lvi.iItem =	65535;
            lvi.iSubItem = 0;
            lvi.lParam = (LPARAM)pItem;
            switch (pItem->wPort) {
            case 21:
                lvi.iImage = 1;
                break;
            case 23:
                lvi.iImage = 2;
                break;
            case 25:
                lvi.iImage = 3;
                break;
            case 79:
                lvi.iImage = 4;
                break;
            case 80:
                lvi.iImage = 5;
                break;
            case 110:
                lvi.iImage = 6;
                break;
            case 135:
                lvi.iImage = 7;
                break;
            case 139:
                lvi.iImage = 8;
                break;
            case 1080:
            case 8080:
                lvi.iImage = 9;
                break;
            case 1433:
                lvi.iImage = 10;
                break;
            case 3389:
                lvi.iImage = 11;
                break;
            default:
                lvi.iImage = 0;
            }
            value = ListView_InsertItem(g_hwndListView, &lvi);
            ListView_EnsureVisible(g_hwndListView, value, TRUE);
            sprintf(strString, "Opened port:%d", nItemCount);
            SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)3, (LPARAM)strString);
            if (isGetBanner && ((thdINFO[intCurThread].wPort == 21) || (thdINFO[intCurThread].wPort == 23) || (thdINFO[intCurThread].wPort == 25) ||	(thdINFO[intCurThread].wPort == 79)	|| (thdINFO[intCurThread].wPort == 80) || (thdINFO[intCurThread].wPort == 110) )) {
                pItem->lpstrBanner =	(LPSTR)c_szGetBanner;
                ListView_Update(g_hwndListView, value);
                if (thdINFO[intCurThread].wPort == 80)
                    send(sockfd, "GET HEAD HTTP/1.1\n\n", 20, 0);
                ZeroMemory(strString, sizeof(strString));
                for (intINT = 0; intINT < nTimeOut * 20; intINT++) {
                    if (isStopForce)
                        break;
                    Sleep(10);
                    if (recv(sockfd, strString, sizeof(strString), 0) > 0)
                        break;
                }
                if ((thdINFO[intCurThread].wPort == 80) && (pPoint1 = strstr(strString, "Server:"))) {
                    pPoint1 += 8;
                    if (	(pPoint2 = strchr(pPoint1, '\r')) || (pPoint2 = strchr(pPoint1, '\n')) )
                        * pPoint2 = '\0';
                } else
                    pPoint1 = strString;
                pPoint2 = LocalAlloc(LMEM_FIXED, strlen(pPoint1) + 1);
                strcpy(pPoint2,	pPoint1);
                pItem->lpstrBanner = (LPSTR)( ( (isStopForce) ? c_szCancelBanner : pPoint2 ) );
                ListView_Update(g_hwndListView, value);
            }
        }
    }
    nScannedPort++;
    sprintf(strString, "Completed:%d%%", nScannedPort * 100 / ((isUseResultIP ? dwStartIP : (dwEndIP - dwStartIP + 1 - nSkipHost)) * (nPortCount * isUsePortList + (nEndPort - nStartPort + 1)*isUsePortRange)));
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)1, (LPARAM)strString);
    thdINFO[intCurThread].wPort = 0;
    nThreadNum--;
    sprintf(strString, "Active thread:%d", nThreadNum);
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)2, (LPARAM)strString);
    closesocket(sockfd);
}
BOOL WINAPI	SaveResult(char	*strFileName, BOOL isSaveSelected) {
    if (fpFile = fopen(strFileName, "w")) {
        for (i = 0; i < nItemCount; i++) {
            if (isSaveSelected && (!ListView_GetItemState(g_hwndListView, i, LVIS_SELECTED)))
                continue;
            ListView_GetItemText(g_hwndListView, i, 0, strTemp, 16);
            fputs(strTemp, fpFile);
            strTemp[0] = '\0';
            ListView_GetItemText(g_hwndListView, i, 1, strTemp, 6);
            if (strTemp[0]) {
                fputs(":", fpFile);
                fputs(strTemp, fpFile);
                strTemp[0] = '\0';
                ListView_GetItemText(g_hwndListView, i, 2, strTemp, sizeof(strTemp));
                if (strTemp[0]) {
                    fputs("\t", fpFile);
                    for (p = strTemp; *p; p++) {
                        if (*p == '\n' || *p == '\r')
                            *p = ' ';
                    }
                    fputs(strTemp, fpFile);
                }
            }
            fputs("\n", fpFile);
        }
        fclose(fpFile);
        return TRUE;
    }
    return FALSE;
}
BOOL WINAPI	LoadResult(char	*strFileName) {
    LV_ITEM lvi;
    char *pTemp;
    if (fpFile = fopen(strFileName, "r")) {
        if (!((GetMenuState(g_hMenu, IDC_KEEPHISTORY, MF_BYCOMMAND) & MF_CHECKED))) {
            ListView_DeleteAllItems(g_hwndListView);
            nItemCount = 0;
            SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)3, (LPARAM)"Opened port:0");
        }
        while (fgets(strTemp, sizeof(strTemp), fpFile)) {
            if (	(p = strchr(strTemp, ':'))	|| (p = strchr(strTemp, ',')) || (p = strchr(strTemp, ';')) || (p = strchr(strTemp, '\t')) )
                * (p++) = '\0';
            if (inet_addr(strTemp) != INADDR_NONE) {
                ITEMINFO *pItem	= LocalAlloc(LPTR, sizeof(ITEMINFO));
                pItem->dwAddr = ntohl(inet_addr(strTemp));
                if (p) {
                    pItem->wPort = atoi(p);
                    if (	(pTemp = strchr(p, '\t')) || (pTemp = strchr(p, ':'))	|| (pTemp = strchr(p, ';')) ||	(pTemp = strchr(p, '@')) ) {
                        *(pTemp++) = '\0';
                        if (	(p = strchr(pTemp, '\n')) || (p = strchr(pTemp, '\r')) )
                            * p = '\0';
                        p = LocalAlloc(LMEM_FIXED, strlen(pTemp) + 1);
                        strcpy(p, pTemp);
                        pItem->lpstrBanner = p;
                    }
                }
                nItemCount++;
                lvi.mask = LVIF_TEXT | LVIF_IMAGE |	LVIF_PARAM;
                lvi.pszText	= LPSTR_TEXTCALLBACK;
                lvi.iItem =	65535;
                lvi.iSubItem = 0;
                lvi.lParam = (LPARAM)pItem;
                switch (pItem->wPort) {
                case 21:
                    lvi.iImage = 1;
                    break;
                case 23:
                    lvi.iImage = 2;
                    break;
                case 25:
                    lvi.iImage = 3;
                    break;
                case 79:
                    lvi.iImage = 4;
                    break;
                case 80:
                    lvi.iImage = 5;
                    break;
                case 110:
                    lvi.iImage = 6;
                    break;
                case 135:
                    lvi.iImage = 7;
                    break;
                case 139:
                    lvi.iImage = 8;
                    break;
                case 1080:
                case 8080:
                    lvi.iImage = 9;
                    break;
                case 1433:
                    lvi.iImage = 10;
                    break;
                case 3389:
                    lvi.iImage = 11;
                    break;
                default:
                    lvi.iImage = 0;
                }
                ListView_EnsureVisible(g_hwndListView, ListView_InsertItem(g_hwndListView, &lvi), TRUE);
                sprintf(strTemp, "Opened port:%d", nItemCount);
                SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)3, (LPARAM)strTemp);
            }
        }
        fclose(fpFile);
        return TRUE;
    }
    return FALSE;
}
void WINAPI	ResolveDomain() {
    int intINT;
    char strString[50];
    HOSTENT *hstName;
    isStopForce = FALSE;
    nThreadNum = 1;
    dwStartIP = GetTickCount();
    EnableWindow(GetDlgItem(g_hWnd, IDC_SCAN), 0);
    EnableWindow(GetDlgItem(g_hWnd, IDC_STOP), 1);
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, (LPARAM)c_szResolve);
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)1, (LPARAM)"Please wait...");
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)2, (LPARAM)"Active thread:1");
    for (intINT = 0; intINT < nItemCount; intINT++) {
        if (isStopForce)
            break;
        if (ListView_GetItemState(g_hwndListView, intINT, LVIS_SELECTED)) {
            ListView_EnsureVisible(g_hwndListView, intINT, TRUE);
            ListView_SetItemText(g_hwndListView, intINT, 2, (LPSTR)c_szResolve);
            ListView_GetItemText(g_hwndListView, intINT, 0, strString, sizeof(strString));
            dwEndIP = inet_addr(strString);
            hstName = gethostbyaddr((char *)&dwEndIP, 4, PF_INET);
            strcpy(strString, hstName ? hstName->h_name : "Cannot resolve domain name");
            ListView_SetItemText(g_hwndListView, intINT, 2, strString);
        }
    }
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)0, isStopForce ? (LPARAM)"Aborted" : (LPARAM)"Completed");
    sprintf(strString, "Cost %dms", GetTickCount() - dwStartIP);
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)1, (LPARAM)strString);
    nThreadNum = 0;
    SendMessage(g_hwndStatus, SB_SETTEXT, (WPARAM)2, (LPARAM)"Active thread:0");
    EnableWindow(GetDlgItem(g_hWnd, IDC_SCAN), 1);
    EnableWindow(GetDlgItem(g_hWnd, IDC_STOP), 0);
}
