using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using Authentication.Core;

namespace Authentication.Windows;

internal sealed partial class OwnedRequestHost
{
    private const uint CloseMessage = 0x8001; // WM_APP + 1; scalar, owned-window only.
    private const int CancelId = 2; // IDCANCEL, also used by IsDialogMessage for Escape.
    private const uint ParentStyle = 0x00ca0000; // WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX.
    [ThreadStatic] private static OwnedRequestHost? currentHost;
    // Native resources below belong exclusively to the creating thread.
    private nint nativeParent;
    private nint cancelButton;
    private nint instance;
    private nint font;
    private ushort windowClass;
    private string? className;
    private int lineHeight;

    private unsafe nint CreateNativeParent()
    {
        instance = GetModuleHandleW(null);
        if (instance == 0) throw new InvalidOperationException("The window module is unavailable.");
        var metrics = new NonClientMetrics { Size = (uint)sizeof(NonClientMetrics) };
        if (SystemParametersInfoW(0x0029, metrics.Size, &metrics, 0) == 0)
            throw new InvalidOperationException("System presentation settings are unavailable.");
        font = CreateFontIndirectW(&metrics.MessageFont);
        if (font == 0) throw new InvalidOperationException("The system message font is unavailable.");
        lineHeight = checked(Math.Max(16, Math.Abs(metrics.MessageFont.Height) * 3 / 2));

        className = "Authentication.OwnedRequest." + Guid.NewGuid().ToString("N");
        fixed (char* name = className)
        {
            var definition = new WindowClass
            {
                Size = (uint)sizeof(WindowClass),
                Procedure = &WindowProcedure,
                Instance = instance,
                Cursor = LoadCursorW(0, (nint)32512), // Shared IDC_ARROW, never destroyed here.
                Background = 16, // COLOR_BTNFACE + 1, a system-managed class brush.
                ClassName = name,
            };
            if (definition.Cursor == 0)
                throw new InvalidOperationException("The system cursor is unavailable.");
            windowClass = RegisterClassExW(&definition);
        }
        if (windowClass == 0) throw new InvalidOperationException("Owned window registration failed.");

        var rectangle = new Rectangle { Right = checked(lineHeight * 36), Bottom = checked(lineHeight * 16) };
        if (AdjustWindowRectEx(&rectangle, ParentStyle, 0, 0) == 0)
            throw new InvalidOperationException("Owned window sizing failed.");
        // No WS_VISIBLE. Even cancellation during native creation can only leave
        // a hidden parent, which is destroyed by this same thread's finally block.
        nativeParent = CreateWindowExW(0, className, "hcoona/microsoft-authentication-cli",
            ParentStyle, int.MinValue, int.MinValue, checked(rectangle.Right - rectangle.Left),
            checked(rectangle.Bottom - rectangle.Top), 0, 0, instance, 0);
        if (nativeParent == 0) throw new InvalidOperationException("Owned window creation failed.");
        return nativeParent;
    }

    private void CreateNativeControls(nint window, ClientProfile admittedProfile)
    {
        var text = $"Profile: {admittedProfile.Name}\r\nRegistration owner: {admittedProfile.RegistrationOwner}"
            + "\r\n\r\nThe authentication provider controls the sign-in and consent display. "
            + "Use that display to complete authentication, or choose Cancel to stop this request.";
        var label = CreateWindowExW(0, "Static", text,
            0x50000080, // WS_CHILD | WS_VISIBLE | SS_NOPREFIX: metadata is plain text.
            lineHeight, lineHeight, checked(lineHeight * 34), checked(lineHeight * 11),
            window, 0, instance, 0);
        if (label == 0) throw new InvalidOperationException("Owned presentation creation failed.");
        _ = SendMessageW(label, 0x0030, (nuint)font, 0); // WM_SETFONT; same UI thread.
        cancelButton = CreateWindowExW(0, "Button", "Cancel",
            0x50010001, // WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON.
            checked(lineHeight * 28), checked(lineHeight * 13), checked(lineHeight * 7),
            checked(lineHeight * 2), window, CancelId, instance, 0);
        if (cancelButton == 0) throw new InvalidOperationException("Owned Cancel control creation failed.");
        _ = SendMessageW(cancelButton, 0x0030, (nuint)font, 0);
    }

    private static void ShowNativeParent(nint window)
    {
        // Synchronous on the creating thread. NOACTIVATE/NOZORDER avoid controlling
        // another application; SHOWWINDOW does not inherit launcher STARTUPINFO state.
        if (SetWindowPos(window, 0, 0, 0, 0, 0, 0x0057) == 0)
            throw new InvalidOperationException("Owned window display failed.");
    }

    private unsafe void PumpNativeMessages(nint window)
    {
        while (!IsTerminal)
        {
            Message message;
            var result = GetMessageW(&message, 0, 0, 0);
            if (result == -1) throw new InvalidOperationException("Owned message retrieval failed.");
            if (result == 0)
            {
                if (!IsTerminal) FailHost();
                return;
            }
            if (IsTerminal) return;
            if (IsDialogMessageW(window, &message) != 0) continue;
            _ = TranslateMessage(&message);
            _ = DispatchMessageW(&message);
        }
    }

    private static void PostOwnedClose(nint window)
    {
        if (PostMessageW(window, CloseMessage, 0, 0) == 0)
            throw new InvalidOperationException("Owned window closure could not be posted.");
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvStdcall)])]
    private static nint WindowProcedure(nint window, uint message, nuint parameter, nint detail)
    {
        var host = currentHost;
        try
        {
            if (host is null) return DefWindowProcW(window, message, parameter, detail);
            host.checkpoint?.Invoke(OwnedHostCheckpoint.MessageDispatch, window);
            switch (message)
            {
                case 0x0010: // WM_CLOSE: explicit user cancellation, never internal closure.
                    host.CancelFromWindow();
                    return 0;
                case 0x0111 when (parameter & 0xffff) == CancelId
                    && ((parameter >> 16) & 0xffff) == 0
                    && (detail == 0 || detail == host.cancelButton): // WM_COMMAND / BN_CLICKED.
                case 0x0100 when parameter == 0x1b: // WM_KEYDOWN / VK_ESCAPE.
                    host.CancelFromWindow();
                    return 0;
                case CloseMessage:
                    return 0; // The terminal loop exits into creating-thread cleanup.
                case 0x0002: // WM_DESTROY.
                    if (!host.IsTerminal) host.FailHost();
                    PostQuitMessage(0);
                    return 0;
                default:
                    return DefWindowProcW(window, message, parameter, detail);
            }
        }
        catch (Exception)
        {
            // Even a failing notification must never unwind through the native ABI.
            try { host?.FailHost(); }
            catch (Exception) { }
            return message == 0x0001 ? -1 : 0; // Fail WM_CREATE or WM_NCCREATE safely.
        }
    }

    private void CleanupNative()
    {
        // Destruction sends callbacks synchronously and destroys child controls.
        // Keep the context and font alive until it has actually returned successfully.
        if (nativeParent != 0)
        {
            if (DestroyWindow(nativeParent) == 0)
                throw new InvalidOperationException("Owned window destruction failed.");
            nativeParent = 0;
            cancelButton = 0;
        }
        if (font != 0)
        {
            if (DeleteObject(font) == 0)
                throw new InvalidOperationException("Owned font release failed.");
            font = 0;
        }
        if (windowClass != 0)
        {
            if (UnregisterClassW(className!, instance) == 0)
                throw new InvalidOperationException("Owned window class release failed.");
            windowClass = 0;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct WindowClass
    {
        internal uint Size;
        internal uint Style;
        internal delegate* unmanaged[Stdcall]<nint, uint, nuint, nint, nint> Procedure;
        internal int ClassExtra;
        internal int WindowExtra;
        internal nint Instance;
        internal nint Icon;
        internal nint Cursor;
        internal nint Background;
        internal char* MenuName;
        internal char* ClassName;
        internal nint SmallIcon;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Message
    {
        internal nint Window;
        internal uint Id;
        internal nuint Parameter;
        internal nint Detail;
        internal uint Time;
        internal int X;
        internal int Y;
        internal uint Private;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Rectangle
    {
        internal int Left;
        internal int Top;
        internal int Right;
        internal int Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct LogicalFont
    {
        internal int Height;
        internal int Width;
        internal int Escapement;
        internal int Orientation;
        internal int Weight;
        internal byte Italic;
        internal byte Underline;
        internal byte StrikeOut;
        internal byte CharacterSet;
        internal byte OutputPrecision;
        internal byte ClipPrecision;
        internal byte Quality;
        internal byte PitchAndFamily;
        internal fixed char FaceName[32];
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NonClientMetrics
    {
        internal uint Size;
        internal int BorderWidth;
        internal int ScrollWidth;
        internal int ScrollHeight;
        internal int CaptionWidth;
        internal int CaptionHeight;
        internal LogicalFont CaptionFont;
        internal int SmallCaptionWidth;
        internal int SmallCaptionHeight;
        internal LogicalFont SmallCaptionFont;
        internal int MenuWidth;
        internal int MenuHeight;
        internal LogicalFont MenuFont;
        internal LogicalFont StatusFont;
        internal LogicalFont MessageFont;
        internal int PaddedBorderWidth;
    }

    [LibraryImport("kernel32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint GetModuleHandleW(string? name);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int SystemParametersInfoW(uint action, uint size, NonClientMetrics* metrics, uint flags);

    [LibraryImport("gdi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial nint CreateFontIndirectW(LogicalFont* font);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint LoadCursorW(nint instance, nint cursor);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial ushort RegisterClassExW(WindowClass* definition);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int AdjustWindowRectEx(Rectangle* rectangle, uint style, int menu, uint extendedStyle);

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint CreateWindowExW(uint extendedStyle, string className, string text, uint style,
        int x, int y, int width, int height, nint parent, nint menu, nint instance, nint parameter);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint SendMessageW(nint window, uint message, nuint parameter, nint detail);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int SetWindowPos(nint window, nint insertAfter, int x, int y, int width, int height, uint flags);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int GetMessageW(Message* message, nint window, uint minimum, uint maximum);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int IsDialogMessageW(nint window, Message* message);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial int TranslateMessage(Message* message);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static unsafe partial nint DispatchMessageW(Message* message);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int PostMessageW(nint window, uint message, nuint parameter, nint detail);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial nint DefWindowProcW(nint window, uint message, nuint parameter, nint detail);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial void PostQuitMessage(int code);

    [LibraryImport("user32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int DestroyWindow(nint window);

    [LibraryImport("gdi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int DeleteObject(nint resource);

    [LibraryImport("user32.dll", StringMarshalling = StringMarshalling.Utf16)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static partial int UnregisterClassW(string className, nint instance);
}
