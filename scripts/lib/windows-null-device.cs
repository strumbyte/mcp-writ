using System;
using System.ComponentModel;
using System.IO;
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
        bool directory;
        RawSecurityDescriptor directoryBefore;

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
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool SetKernelObjectSecurity(SafeFileHandle handle, uint info, byte[] descriptor);

        static void Check(uint error, string operation) {
            if (error != 0) throw new Win32Exception((int)error, operation);
        }

        public static NullDeviceAccess Grant(string path) {
            return GrantObject(path, ReadWrite, false);
        }

        public static NullDeviceAccess GrantDirectoryMetadata(string path) {
            if (!Directory.Exists(path)) throw new DirectoryNotFoundException(path);
            // LIST_DIRECTORY | TRAVERSE | READ_ATTRIBUTES, this directory only.
            // GetLongPathNameW queries parents even when the leaf is readable.
            return GrantObject(path, 0xa1, true);
        }

        static void WriteDirectoryDacl(SafeFileHandle handle, RawAcl dacl, bool protect) {
            // SetSecurityInfo can walk descendants even with a non-inherited
            // new ACE. Never propagate a host-prerequisite change down a drive.
            // A fresh descriptor avoids carrying auto-inheritance request
            // flags from the original descriptor into this single-object write.
            var sd = new RawSecurityDescriptor(ControlFlags.DiscretionaryAclPresent,
                null, null, null, dacl);
            var bytes = new byte[sd.BinaryLength];
            sd.GetBinaryForm(bytes, 0);
            uint info = DaclInformation | (protect ? 0x80000000u : 0x20000000u);
            if (!SetKernelObjectSecurity(handle, info, bytes))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "Write directory metadata DACL");
        }

        static NullDeviceAccess GrantObject(string path, int mask, bool directory) {
            var access = new NullDeviceAccess { directory = directory };
            try {
                // A device must be addressed by handle. Get-Acl/Set-Acl on
                // the NUL pathname do not reliably change its device DACL.
                access.handle = CreateFileW(path, 0x60000, 3,
                    IntPtr.Zero, 3, directory ? 0x02000000u : 0u, IntPtr.Zero);
                    // READ_CONTROL | WRITE_DAC; BACKUP_SEMANTICS for directories.
                if (access.handle.IsInvalid)
                    throw new Win32Exception(Marshal.GetLastWin32Error(),
                        "Open " + path + " for CI setup (requires an elevated runner)");
                IntPtr owner, group, sacl;
                Check(GetSecurityInfo(access.handle, FileObject, DaclInformation,
                    out owner, out group, out access.originalDacl, out sacl,
                    out access.descriptor), "Read CI prerequisite DACL");
                if (access.originalDacl == IntPtr.Zero)
                    throw new InvalidOperationException("Refusing to replace a null DACL");
                var bytes = new byte[GetSecurityDescriptorLength(access.descriptor)];
                Marshal.Copy(access.descriptor, bytes, 0, bytes.Length);
                if (directory) access.directoryBefore = new RawSecurityDescriptor(bytes, 0);
                byte[] acl;
                if (directory) {
                    // Keep existing ACEs byte-for-byte, including inheritance.
                    var raw = new RawSecurityDescriptor(bytes, 0).DiscretionaryAcl;
                    int index = 0;
                    while (index < raw.Count && (raw[index].AceFlags & AceFlags.Inherited) == 0)
                        index++;
                    raw.InsertAce(index, new CommonAce(AceFlags.None, AceQualifier.AccessAllowed,
                        mask, new SecurityIdentifier("S-1-15-2-1"), false, null));
                    acl = new byte[raw.BinaryLength];
                    raw.GetBinaryForm(acl, 0);
                } else {
                    var sd = new CommonSecurityDescriptor(false, false, bytes, 0);
                    sd.DiscretionaryAcl.AddAccess(AccessControlType.Allow,
                        new SecurityIdentifier("S-1-15-2-1"), mask,
                        InheritanceFlags.None, PropagationFlags.None);
                    acl = new byte[sd.DiscretionaryAcl.BinaryLength];
                    sd.DiscretionaryAcl.GetBinaryForm(acl, 0);
                }
                var pinned = GCHandle.Alloc(acl, GCHandleType.Pinned);
                try {
                    if (directory) WriteDirectoryDacl(access.handle, new RawAcl(acl, 0),
                        (access.directoryBefore.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0);
                    else Check(SetSecurityInfo(access.handle, FileObject, DaclInformation,
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
                    if (directory) WriteDirectoryDacl(handle, directoryBefore.DiscretionaryAcl,
                        (directoryBefore.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0);
                    else Check(SetSecurityInfo(handle, FileObject, DaclInformation,
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
