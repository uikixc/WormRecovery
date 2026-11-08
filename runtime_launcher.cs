// Single distributable; cache contents are verified before loading any target code.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.IO.Pipes;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

[assembly: System.Runtime.Versioning.TargetFramework(".NETFramework,Version=v4.6.2")]

internal static class RuntimeLauncher {
    private static readonly SecurityIdentifier Admin = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier SystemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
    private sealed class Item { public string Name, Hash; public long Size; }
    private sealed class StartupWindow : Form {
        public bool Cancelled;
        private readonly Label status = new Label();
        private readonly ProgressBar progress = new ProgressBar();
        public StartupWindow() {
            Text = "WormRecovery · 正在启动"; Width = 470; Height = 170;
            StartPosition = FormStartPosition.CenterScreen; FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            status.SetBounds(22, 20, 410, 45); status.Text = "正在启动 WormRecovery…";
            progress.SetBounds(22, 78, 410, 20); Controls.Add(status); Controls.Add(progress);
            FormClosing += (sender, e) => { Cancelled = true; e.Cancel = true; };
        }
        public void Report(string text, int done, int total) {
            status.Text = text; progress.Value = total == 0 ? 0 : Math.Min(100, (int)(100L * done / total));
            Application.DoEvents();
            if (Cancelled) throw new OperationCanceledException("Startup cancelled.");
        }
    }
    private static StartupWindow startup;
    private static readonly Stopwatch uiClock = Stopwatch.StartNew();
    private static readonly int uiThread = System.Threading.Thread.CurrentThread.ManagedThreadId;
    private static void Progress(string text, int done, int total) {
        if (System.Threading.Thread.CurrentThread.ManagedThreadId != uiThread || startup == null) return;
        if (done != 0 && done != total && uiClock.ElapsedMilliseconds < 80) return;
        uiClock.Restart(); startup.Report(text, done, total);
    }
    private static string Hash(Stream stream) {
        using (var sha = SHA256.Create()) return BitConverter.ToString(sha.ComputeHash(stream)).Replace("-", "").ToLowerInvariant();
    }
    private static string ExtendedPath(string path) {
        if (path.StartsWith(@"\\?\", StringComparison.Ordinal)) return path;
        string full = Path.GetFullPath(path);
        return full.StartsWith(@"\\", StringComparison.Ordinal) ? @"\\?\UNC\" + full.Substring(2) : @"\\?\" + full;
    }
    private static void PlainPath(string path) {
        for (var current = new DirectoryInfo(ExtendedPath(path)); current != null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Runtime path contains a reparse point: " + current.FullName);
    }
    private static DirectorySecurity RootSecurity() {
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false); acl.SetOwner(Admin);
        foreach (var sid in new [] { Admin, SystemSid })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        return acl;
    }
    private static void CheckSecurity(FileSystemSecurity acl) {
        var owner = (SecurityIdentifier)acl.GetOwner(typeof(SecurityIdentifier));
        if (!owner.Equals(Admin) && !owner.Equals(SystemSid)) throw new IOException("Runtime cache owner is not trusted.");
        bool adminAllowed = false;
        foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (rule.AccessControlType == AccessControlType.Allow && !sid.Equals(Admin) && !sid.Equals(SystemSid))
                throw new IOException("Runtime cache permissions are not private to administrators.");
            if (rule.AccessControlType == AccessControlType.Allow && sid.Equals(Admin)) adminAllowed = true;
        }
        if (!adminAllowed) throw new IOException("Runtime cache administrator access is missing.");
    }
    private static Dictionary<string, Item> ReadManifest(out string identity) {
        return ReadManifest("runtime-manifest.tsv", true, out identity);
    }
    private static Dictionary<string, Item> ReadManifest(string resource, bool requireEntry, out string identity) {
        byte[] bytes;
        using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource))
        using (var memory = new MemoryStream()) { stream.CopyTo(memory); bytes = memory.ToArray(); }
        using (var memory = new MemoryStream(bytes)) identity = Hash(memory);
        var items = new Dictionary<string, Item>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in Encoding.UTF8.GetString(bytes).Split('\n')) {
            if (line.Length == 0) continue;
            var fields = line.Split('\t'); long size;
            if (fields.Length != 3 || fields[0].Length != 64 || !long.TryParse(fields[1], NumberStyles.None, CultureInfo.InvariantCulture, out size) || size < 0)
                throw new IOException("Invalid embedded runtime manifest.");
            string name = fields[2];
            if (name.Length == 0 || name.Contains("\\") || name.Contains(":") || name.StartsWith("/") || name.Split('/').Any(x => x.Length == 0 || x == "." || x == ".."))
                throw new IOException("Invalid embedded runtime filename.");
            items.Add(name, new Item { Name = name, Hash = fields[0], Size = size });
        }
        if (requireEntry && !items.ContainsKey(LauncherConfig.Entry)) throw new IOException("Runtime entry is missing.");
        return items;
    }
    private static string ItemPath(string root, string name) { return Path.Combine(root, name.Replace('/', Path.DirectorySeparatorChar)); }
    private static void Extract(string stage, Dictionary<string, Item> items, string resource = "runtime.zip") {
        stage = ExtendedPath(stage);
        Directory.CreateDirectory(stage, RootSecurity());
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        Progress("正在准备程序运行文件，仅首次需要…", 0, items.Count);
        using (var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(resource))
        using (var zip = new ZipArchive(stream, ZipArchiveMode.Read)) {
            foreach (var entry in zip.Entries) {
                Item item;
                if (!items.TryGetValue(entry.FullName, out item) || !found.Add(entry.FullName) || entry.Length != item.Size)
                    throw new IOException("Runtime archive does not match its manifest.");
                string path = ItemPath(stage, item.Name); Directory.CreateDirectory(Path.GetDirectoryName(path));
                using (var input = entry.Open()) using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) {
                    byte[] buffer = new byte[1024 * 1024]; long written = 0; int count;
                    while ((count = input.Read(buffer, 0, buffer.Length)) != 0) {
                        written += count; if (written > item.Size) throw new IOException("Runtime archive exceeds its manifest.");
                        output.Write(buffer, 0, count);
                    }
                    if (written != item.Size) throw new IOException("Runtime archive is incomplete.");
                    // The cache is reproducible. A crash can leave incomplete bytes,
                    // which the full verification below rejects before execution.
                    output.Flush();
                }
                Progress("正在准备程序运行文件，仅首次需要…", found.Count, items.Count);
            }
        }
        if (found.Count != items.Count) throw new IOException("Runtime archive is incomplete.");
    }
    // Handles deny writes and deletes until the launched process exits. The
    // cache's administrator-only ACL also excludes unelevated processes.
    private static List<FileStream> VerifyAndLock(string root, Dictionary<string, Item> items) {
        root = ExtendedPath(root);
        var handles = new List<FileStream>();
        Progress("正在校验程序运行文件…", 0, items.Count);
        try {
            var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var directories = new Stack<string>(); directories.Push(root);
            while (directories.Count != 0) {
                string dir = directories.Pop(); PlainPath(dir); CheckSecurity(Directory.GetAccessControl(dir));
                foreach (string child in Directory.GetDirectories(dir)) directories.Push(child);
                foreach (string file in Directory.GetFiles(dir)) {
                    if ((File.GetAttributes(file) & FileAttributes.ReparsePoint) != 0) throw new IOException("Runtime cache contains a reparse point.");
                    CheckSecurity(File.GetAccessControl(file));
                    string name = file.Substring(root.Length + 1).Replace(Path.DirectorySeparatorChar, '/'); Item item;
                    if (!items.TryGetValue(name, out item) || !found.Add(name)) throw new IOException("Unexpected runtime cache file.");
                    var handle = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read); handles.Add(handle);
                    if (handle.Length != item.Size || Hash(handle) != item.Hash) throw new IOException("Runtime cache verification failed: " + name);
                    Progress("正在校验程序运行文件…", found.Count, items.Count);
                }
            }
            if (found.Count != items.Count) throw new IOException("Runtime cache is incomplete.");
            return handles;
        } catch { foreach (var handle in handles) handle.Dispose(); throw; }
    }
    private sealed class OptionalBroker : IDisposable {
        private readonly string cache;
        private readonly System.Threading.Thread worker;
        private readonly object gate = new object();
        private NamedPipeServerStream pipe;
        private bool closed;
        private List<FileStream> locks;
        private string ready;
        public readonly string Name = "WormRecovery-" + Guid.NewGuid().ToString("N");
        public OptionalBroker(string cachePath) {
            cache = cachePath;
            worker = new System.Threading.Thread(Serve); worker.IsBackground = true; worker.Start();
        }
        private string Prepare() {
            if (ready != null) return ready;
            string identity; var items = ReadManifest("optional-manifest.tsv", false, out identity);
            if (items.Count == 0) throw new IOException("Optional engines are not bundled.");
            string root = Path.Combine(cache, identity);
            using (var mutex = new System.Threading.Mutex(false, "Global\\WormRecoveryRuntime-" + identity)) {
                bool acquired = false;
                try {
                    try { acquired = mutex.WaitOne(TimeSpan.FromMinutes(3)); }
                    catch (System.Threading.AbandonedMutexException) { acquired = true; }
                    if (!acquired) throw new IOException("Optional engine preparation is busy.");
                    PlainPath(cache); CheckSecurity(Directory.GetAccessControl(ExtendedPath(cache)));
                    if (!Directory.Exists(ExtendedPath(root))) {
                        string stage = Path.Combine(cache, identity + ".stage-" + Guid.NewGuid().ToString("N"));
                        Extract(stage, items, "optional.zip");
                        Directory.Move(ExtendedPath(stage), ExtendedPath(root));
                    }
                    locks = VerifyAndLock(root, items);
                    ready = ItemPath(root, "_internal/engines");
                } finally { if (acquired) mutex.ReleaseMutex(); }
            }
            return ready;
        }
        private void Serve() {
            try {
                while (true) {
                    var security = new PipeSecurity(); security.SetAccessRuleProtection(true, false);
                    foreach (var sid in new [] { Admin, SystemSid })
                        security.AddAccessRule(new PipeAccessRule(sid, PipeAccessRights.FullControl, AccessControlType.Allow));
                    using (var current = new NamedPipeServerStream(Name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 4096, 4096, security)) {
                        lock (gate) { if (closed) return; pipe = current; }
                        current.WaitForConnection();
                        // No caller-selected path, command or target is accepted.
                        string response;
                        try { response = "OK\t" + Prepare(); }
                        catch (Exception ex) { response = "ERROR\t" + ex.Message.Replace('\r', ' ').Replace('\n', ' '); }
                        byte[] bytes = Encoding.UTF8.GetBytes(response + "\n");
                        current.Write(bytes, 0, bytes.Length); current.Flush();
                    }
                    lock (gate) { pipe = null; if (closed) return; }
                }
            } catch (IOException) { } catch (ObjectDisposedException) { }
        }
        public void Dispose() {
            lock (gate) { closed = true; if (pipe != null) pipe.Dispose(); }
            worker.Join();
            if (locks != null) foreach (var handle in locks) handle.Dispose();
        }
    }
    private static string Quote(string value) {
        var b = new StringBuilder("\""); int slashes = 0;
        foreach (char c in value) {
            if (c == '\\') { slashes++; continue; }
            if (c == '"') { b.Append('\\', slashes * 2 + 1); b.Append(c); slashes = 0; continue; }
            b.Append('\\', slashes); slashes = 0; b.Append(c);
        }
        b.Append('\\', slashes * 2); return b.Append('"').ToString();
    }
    [STAThread] private static int Main(string[] args) {
        AppContext.SetSwitch("Switch.System.IO.UseLegacyPathHandling", false);
        AppContext.SetSwitch("Switch.System.IO.BlockLongPaths", false);
        List<FileStream> handles = null;
        OptionalBroker broker = null;
        try {
            if (args.Length == 0) { Application.EnableVisualStyles(); startup = new StartupWindow(); startup.Show(); Progress("正在启动 WormRecovery…", 0, 0); }
            string identity; var items = ReadManifest(out identity);
            string cache = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WormRecoveryRuntime");
            PlainPath(cache); Directory.CreateDirectory(ExtendedPath(cache), RootSecurity()); CheckSecurity(Directory.GetAccessControl(ExtendedPath(cache)));
            string root = Path.Combine(cache, identity);
            using (var mutex = new System.Threading.Mutex(false, "Global\\WormRecoveryRuntime-" + identity)) {
                bool acquired = false;
                try {
                    try {
                        var waiting = Stopwatch.StartNew();
                        while (!(acquired = mutex.WaitOne(100)) && waiting.Elapsed < TimeSpan.FromMinutes(3))
                            Progress("正在等待另一窗口准备离线组件…", 0, 0);
                    } catch (System.Threading.AbandonedMutexException) { acquired = true; }
                    if (!acquired) throw new IOException("Another runtime preparation is still in progress.");
                    if (!Directory.Exists(ExtendedPath(root))) {
                        string stage = Path.Combine(cache, identity + ".stage-" + Guid.NewGuid().ToString("N"));
                        try { Extract(stage, items); }
                        catch (OperationCanceledException) {
                            // Only this invocation's random staging child may be removed.
                            if (Path.GetDirectoryName(Path.GetFullPath(stage)) != Path.GetFullPath(cache)) throw;
                            PlainPath(stage);
                            if (Directory.Exists(ExtendedPath(stage))) Directory.Delete(ExtendedPath(stage), true);
                            throw;
                        }
                        Directory.Move(ExtendedPath(stage), ExtendedPath(root));
                    }
                    handles = VerifyAndLock(root, items);
                } finally { if (acquired) mutex.ReleaseMutex(); }
            }
            broker = new OptionalBroker(cache);
            var start = new ProcessStartInfo(ItemPath(root, LauncherConfig.Entry), string.Join(" ", args.Select(Quote)));
            start.UseShellExecute = false; start.CreateNoWindow = true;
            start.RedirectStandardOutput = true; start.RedirectStandardError = true;
            start.WorkingDirectory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            start.EnvironmentVariables["WORMRECOVERY_LAUNCHER_PATH"] = Assembly.GetExecutingAssembly().Location;
            start.EnvironmentVariables["WORMRECOVERY_LAUNCHER_PID"] = Process.GetCurrentProcess().Id.ToString(CultureInfo.InvariantCulture);
            start.EnvironmentVariables["WORMRECOVERY_RUNTIME_ROOT"] = root;
            start.EnvironmentVariables["WORMRECOVERY_ENGINE_PIPE"] = broker.Name;
            start.EnvironmentVariables["PYINSTALLER_RESET_ENVIRONMENT"] = "1";
            start.EnvironmentVariables.Remove("WORMRECOVERY_ENGINE_ROOT"); start.EnvironmentVariables.Remove("WORMRECOVERY_WORK_ROOT");
            start.EnvironmentVariables.Remove("PYTHONPATH"); start.EnvironmentVariables.Remove("PYTHONHOME");
            foreach (string name in start.EnvironmentVariables.Keys.Cast<string>().ToArray())
                if (name.StartsWith("_PYI_", StringComparison.Ordinal) || name == "_MEIPASS2") start.EnvironmentVariables.Remove(name);
            using (var process = Process.Start(start)) {
                if (startup != null) { startup.Dispose(); startup = null; }
                var stdout = new System.Threading.Thread(() => { try { process.StandardOutput.BaseStream.CopyTo(Console.OpenStandardOutput()); } catch (IOException) {} });
                var stderr = new System.Threading.Thread(() => { try { process.StandardError.BaseStream.CopyTo(Console.OpenStandardError()); } catch (IOException) {} });
                stdout.Start(); stderr.Start(); process.WaitForExit(); stdout.Join(); stderr.Join(); return process.ExitCode;
            }
        } catch (OperationCanceledException) {
            return 2;
        } catch (Exception ex) {
            // Preserve diagnostics for console-free starts without executing an
            // unverified fallback. --help probes must not show a modal dialog.
            try { Console.Error.WriteLine(ex.ToString()); } catch { }
            if (args.Length == 0) MessageBox.Show(ex.Message, "WormRecovery runtime", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        } finally { if (startup != null) startup.Dispose(); if (broker != null) broker.Dispose(); if (handles != null) foreach (var handle in handles) handle.Dispose(); }
    }
}
