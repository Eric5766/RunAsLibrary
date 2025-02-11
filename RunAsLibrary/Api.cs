using Newtonsoft.Json;
using Ookii.Dialogs.WinForms;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace RunAsLibrary
{
    [Flags]
    public enum SecurityRestrictions
    {
        None = 0,
        DenyProgramFiles = 1 << 0,     // ACL restrictions on Program A's directory
        LowIntegrity = 1 << 1,         // Set low integrity level
        BasicJobLimits = 1 << 2       // Basic job limits (die on exception)
    }

    public class Api
    {
        private static string ConfigFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "config.json");

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string name);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, JobObjectInfoType infoType,
            IntPtr lpJobObjectInfo, uint cbJobObjectInfoLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetTokenInformation(IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool SetProcessIntegrityLevel(IntPtr hToken, int dwIntegrityLevel);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr hProcess, uint dwDesiredAccess, out IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static IntPtr GetStructurePointer(object obj)
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(obj));
            Marshal.StructureToPtr(obj, ptr, false);
            return ptr;
        }

        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000;
        private const uint JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x400;
        private const uint JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008;
        private const uint JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100;
        private const uint JOB_OBJECT_LIMIT_PROCESS_TIME = 0x00000002;
        private const uint JOB_OBJECT_LIMIT_WORKINGSET = 0x00000001;
        private const int SECURITY_MANDATORY_LOW_RID = 0x1000;

        private enum JobObjectInfoType
        {
            ExtendedLimitInformation = 9
        }

        private enum TOKEN_INFORMATION_CLASS
        {
            TokenIntegrityLevel = 25
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        public void Create(string NameLog, string Pass)
        {
            if (string.IsNullOrEmpty(NameLog) || string.IsNullOrEmpty(Pass))
            {
                return;
            }

            try
            {
                DirectoryEntry AD = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer");

                try
                {
                    DirectoryEntry existingUser = AD.Children.Find(NameLog, "user");
                    existingUser.Invoke("SetPassword", new object[] { Pass });
                    existingUser.CommitChanges();
                    return;
                }
                catch (Exception) 
                {
                    SecurityIdentifier everyoneSid = new SecurityIdentifier(
                        WellKnownSidType.BuiltinUsersSid,
                        null
                    );
                    string everyone = everyoneSid.Translate(typeof(System.Security.Principal.NTAccount)).ToString();
                    string pattern = @"[^\\]*\\";
                    string usergroup = Regex.Replace(everyone, pattern, "");

                    DirectoryEntry NewUser = AD.Children.Add(NameLog, "user");
                    NewUser.Invoke("SetPassword", new object[] { Pass });
                    NewUser.Invoke("Put", new object[] { "Description", "" });
                    NewUser.CommitChanges();
                    DirectoryEntry grp;
                    grp = AD.Children.Find(usergroup, "group");
                    if (grp != null)
                    {
                        grp.Invoke("Add", new object[] { NewUser.Path.ToString() });
                    }

                    int ADS_UF_DONT_EXPIRE_PASSWD = 0x10000;
                    int userFlags = (int)NewUser.Properties["UserFlags"].Value;
                    NewUser.Properties["UserFlags"].Value = userFlags | ADS_UF_DONT_EXPIRE_PASSWD;

                    NewUser.CommitChanges();
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error creating/updating user: {ex.Message}");
                throw;
            }
        }

        public void Remove(string NameLog)
        {
            DirectoryEntry localDirectory = new DirectoryEntry("WinNT://" + Environment.MachineName.ToString());
            DirectoryEntries users_list = localDirectory.Children;
            DirectoryEntry old_user = users_list.Find(NameLog);
            users_list.Remove(old_user);

            DirectoryInfo userProfileDirectory = new DirectoryInfo(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            string delete_path = Path.Combine(userProfileDirectory.Parent.FullName, NameLog);

            if (!Directory.Exists(delete_path)) { return; }
            var proc1 = new ProcessStartInfo();
            string Command;
            proc1.UseShellExecute = true;
            Command = @"rd /s /q " + delete_path;
            Console.WriteLine(Command);
            proc1.WorkingDirectory = @"C:\Windows\System32";
            proc1.FileName = @"C:\Windows\System32\cmd.exe";
            proc1.Verb = "runas";
            proc1.Arguments = "/c " + Command;
            proc1.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(proc1);
        }

        public void GetInfo(string NameLog)
        {
            if (NameLog != null && NameLog.Length > 0)
            {
                var proc1 = new ProcessStartInfo();
                string Command;
                proc1.UseShellExecute = true;
                Command = @"net user " + NameLog + " && pause";
                proc1.WorkingDirectory = @"C:\Windows\System32";
                proc1.FileName = @"C:\Windows\System32\cmd.exe";
                proc1.Verb = "runas";
                proc1.Arguments = "/c " + Command;
                proc1.WindowStyle = ProcessWindowStyle.Normal;
                Process.Start(proc1);
            }
            else
            {
                var proc1 = new ProcessStartInfo();
                string Command;
                proc1.UseShellExecute = true;
                Command = @"net user && pause";
                proc1.WorkingDirectory = @"C:\Windows\System32";
                proc1.FileName = @"C:\Windows\System32\cmd.exe";
                proc1.Verb = "runas";
                proc1.Arguments = "/c " + Command;
                proc1.WindowStyle = ProcessWindowStyle.Normal;
                Process.Start(proc1);
            }
        }

        public string Get_FolderPath()
        {
            VistaFolderBrowserDialog dlg = new VistaFolderBrowserDialog();
            dlg.ShowNewFolderButton = true;

            if (dlg.ShowDialog() == DialogResult.OK)
            {
                string path_o = dlg.SelectedPath.Replace("\u005C", "\u002F");
                return path_o;
            }
            return "";
        }

        public string Get_Exe()
        {
            using (OpenFileDialog openFileDialog = new OpenFileDialog())
            {
                var fileContent = string.Empty;
                var filePath = string.Empty;
                var path_f = string.Empty;

                openFileDialog.Filter = "Exe file (*.exe)|*.exe";

                if (openFileDialog.ShowDialog() == DialogResult.OK)
                {
                    filePath = openFileDialog.FileName.Replace("\u005C", "\u002F");
                    path_f = Path.GetFileName(filePath);
                    return path_f;
                }
            }
            return "";
        }

        public void run_target(string path, string path_exe, string NameLog, string Pass, string args, string protectedPath, SecurityRestrictions restrictions = SecurityRestrictions.None)
        {
            if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(path_exe) ||
                string.IsNullOrEmpty(NameLog) || string.IsNullOrEmpty(Pass))
            {
                return;
            }

            if (restrictions.HasFlag(SecurityRestrictions.DenyProgramFiles))
            {
                try
                {
                    DirectorySecurity dirSecurity = Directory.GetAccessControl(protectedPath);

                    FileSystemAccessRule rule = new FileSystemAccessRule(
                        NameLog,
                        FileSystemRights.Read | FileSystemRights.ExecuteFile | FileSystemRights.ListDirectory | FileSystemRights.Modify | FileSystemRights.Write | FileSystemRights.FullControl,
                        InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                        PropagationFlags.None,
                        AccessControlType.Deny
                    );;

                    dirSecurity.AddAccessRule(rule);
                    Directory.SetAccessControl(protectedPath, dirSecurity);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Failed to set ACL: {ex.Message}");
                    return;
                }
            }

            string fullExePath = Path.Combine(path, path_exe);
            Directory.SetCurrentDirectory(path);

            var process = new Process();
            var securePassword = new SecureString();

            process.StartInfo.UseShellExecute = false;
            process.StartInfo.FileName = fullExePath;
            process.StartInfo.LoadUserProfile = true;
            process.StartInfo.Verb = "runas";
            process.StartInfo.Domain = System.Environment.UserDomainName;
            process.StartInfo.UserName = NameLog;
            process.StartInfo.Arguments = args;

            if (restrictions.HasFlag(SecurityRestrictions.LowIntegrity))
            {
                process.StartInfo.Environment["__COMPAT_LAYER"] = "RunAsInvoker";
            }

            foreach (char c in Pass)
            {
                securePassword.AppendChar(c);
            }
            process.StartInfo.Password = securePassword;

            try
            {
                process.Start();

                if (restrictions.HasFlag(SecurityRestrictions.BasicJobLimits))
                {
                    IntPtr jobHandle = CreateJobObject(IntPtr.Zero, null);

                    var jobInfo = new JOBOBJECT_BASIC_LIMIT_INFORMATION();

                    if (restrictions.HasFlag(SecurityRestrictions.BasicJobLimits))
                    {
                        jobInfo.LimitFlags |= JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
                    }

                    var extendedInfo = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                    {
                        BasicLimitInformation = jobInfo
                    };

                    IntPtr extendedInfoPtr = GetStructurePointer(extendedInfo);

                    try
                    {
                        SetInformationJobObject(
                            jobHandle,
                            JobObjectInfoType.ExtendedLimitInformation,
                            extendedInfoPtr,
                            (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION)));
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(extendedInfoPtr);
                    }

                    AssignProcessToJobObject(jobHandle, process.Handle);
                }

                if (restrictions.HasFlag(SecurityRestrictions.LowIntegrity))
                {
                    IntPtr hToken;
                    const uint TOKEN_ADJUST_DEFAULT = 0x0080;
                    const uint TOKEN_QUERY = 0x0008;
                    const uint TOKEN_ALL_ACCESS = 0xF01FF;

                    if (OpenProcessToken(process.Handle, TOKEN_ALL_ACCESS, out hToken))
                    {
                        try
                        {
                            SetProcessIntegrityLevel(hToken, SECURITY_MANDATORY_LOW_RID);
                        }
                        finally
                        {
                            CloseHandle(hToken);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Failed to start process or set restrictions: {ex.Message}");
            }
        }

        public void SaveCfg(params KeyValuePair<string, string>[] keyValuePairs)
        {
            Dictionary<string, string> configData = new Dictionary<string, string>();

            if (File.Exists(ConfigFilePath))
            {
                string json = File.ReadAllText(ConfigFilePath);
                configData = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            }

            foreach (var kvp in keyValuePairs)
            {
                configData[kvp.Key] = kvp.Value;
            }

            string jsonString = JsonConvert.SerializeObject(configData);
            File.WriteAllText(ConfigFilePath, jsonString);
        }

        public string ReadCfg(string key)
        {
            if (File.Exists(ConfigFilePath))
            {
                string json = File.ReadAllText(ConfigFilePath);
                Dictionary<string, string> configData = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);

                if (configData.TryGetValue(key, out string value))
                {
                    return value;
                }
            }
            return null;
        }
    }
}