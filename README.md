But what if we Hide the Crashed Process:
```
// Create a sacrifical process
	PROCESS_INFORMATION pi;
	STARTUPINFO si = { sizeof(STARTUPINFO) };
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_HIDE;
	CreateProcess(L"C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);

 // Wait for process initialization
 WaitForInputIdle(pi.hProcess, 1000);```

and now The rest of the code
