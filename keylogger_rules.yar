rule Detect_Basic_Keylogger {
    meta:
        author = "Security Researcher"
        description = "Detects common API imports and strings associated with keyloggers"
        threat_level = "High"

    strings:
        // Core Windows APIs required for low-level keyboard hooking
        $api1 = "SetWindowsHookEx" ascii wide nocase
        $api2 = "CallNextHookEx" ascii wide nocase
        $api3 = "UnhookWindowsHookEx" ascii wide nocase
        $api4 = "GetAsyncKeyState" ascii wide nocase

        // Common hardcoded strings found in basic keyloggers
        $log1 = "[ENTER]" ascii wide
        $log2 = "[BACKSPACE]" ascii wide
        $log3 = "keylog.txt" ascii wide nocase
        
        // Common Python keylogger libraries (if analyzing a python script)
        $py1 = "pynput.keyboard" ascii
        $py2 = "keyboard.Listener" ascii

    condition:
        // Trigger if it has the hooking APIs AND logging strings, 
        // OR if it imports Python keylogger modules
        (3 of ($api*) and 1 of ($log*)) or (any of ($py*))
}