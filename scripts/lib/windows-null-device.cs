using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace McpWrit.Ci {
    public sealed class NullDeviceAccess : IDisposable {
        const uint DaclInformation = 4;
        const int FileObject = 1;
        // FILE_GENERIC_READ | FILE_GENERIC_WRITE, without WRITE_DAC/DELETE.
        const int ReadWrite = 0x12019f;
        SafeFileHandle handle;
        IntPtr descriptor;
        IntPtr originalDacl;
        bool changed;

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern SafeFileHandle CreateFileW(string path, uint access,
            uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("advapi32.dll")]
        static extern uint GetSecurityInfo(SafeFileHandle handle, int type, uint info,
            out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl,
            out IntPtr descriptor);
        [DllImport("advapi32.dll")]
        static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("advapi32.dll")]
        static extern uint SetSecurityInfo(SafeFileHandle handle, int type, uint info,
            IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);
        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr memory);

        static void Check(uint error, string operation) {
            if (error != 0) throw new Win32Exception((int)error, operation);
        }

        public static NullDeviceAccess Grant(string path) {
            var access = new NullDeviceAccess();
            try {
                // A device must be addressed by handle. Get-Acl/Set-Acl on
                // the NUL pathname do not reliably change its device DACL.
                access.handle = CreateFileW(path, 0x60000, 3,
                    IntPtr.Zero, 3, 0, IntPtr.Zero); // READ_CONTROL | WRITE_DAC
                if (access.handle.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Open NUL for CI setup (requires an elevated runner)");
                IntPtr owner, group, sacl;
                Check(GetSecurityInfo(access.handle, FileObject, DaclInformation,
                    out owner, out group, out access.originalDacl, out sacl,
                    out access.descriptor), "Read NUL DACL");
                if (access.originalDacl == IntPtr.Zero)
                    throw new InvalidOperationException("Refusing to replace a null DACL");
                var bytes = new byte[GetSecurityDescriptorLength(access.descriptor)];
                Marshal.Copy(access.descriptor, bytes, 0, bytes.Length);
                var sd = new CommonSecurityDescriptor(false, false, bytes, 0);
                sd.DiscretionaryAcl.AddAccess(AccessControlType.Allow,
                    new SecurityIdentifier("S-1-15-2-1"), ReadWrite,
                    InheritanceFlags.None, PropagationFlags.None);
                var acl = new byte[sd.DiscretionaryAcl.BinaryLength];
                sd.DiscretionaryAcl.GetBinaryForm(acl, 0);
                var pinned = GCHandle.Alloc(acl, GCHandleType.Pinned);
                try {
                    Check(SetSecurityInfo(access.handle, FileObject, DaclInformation,
                        IntPtr.Zero, IntPtr.Zero, pinned.AddrOfPinnedObject(), IntPtr.Zero),
                        "Grant AppContainer NUL read/write");
                    access.changed = true;
                } finally { pinned.Free(); }
                return access;
            } catch {
                access.Dispose();
                throw;
            }
        }

        public void Dispose() {
            try {
                if (changed) {
                    Check(SetSecurityInfo(handle, FileObject, DaclInformation,
                        IntPtr.Zero, IntPtr.Zero, originalDacl, IntPtr.Zero),
                        "Restore original NUL DACL");
                    changed = false;
                }
            } finally {
                if (descriptor != IntPtr.Zero) {
                    LocalFree(descriptor);
                    descriptor = IntPtr.Zero;
                }
                if (handle != null) { handle.Dispose(); handle = null; }
            }
        }
    }
}
