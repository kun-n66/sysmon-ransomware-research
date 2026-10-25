using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.IO.Ports;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;

namespace SysmonSerial
{
    internal static class Wire
    {
        public const int Version = 1;
        public static string Utc() { return DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture); }
        public static Dictionary<string, object> Message(string type, string run)
        {
            return new Dictionary<string, object> { { "v", Version }, { "type", type }, { "run_id", run } };
        }
        public static string Encode(Dictionary<string, object> message)
        {
            var json = new JavaScriptSerializer { MaxJsonLength = 8 * 1024 * 1024 };
            return json.Serialize(message) + "\n";
        }
    }

    internal sealed class Session : IDisposable
    {
        private readonly Action<Dictionary<string, object>> send;
        private readonly Action<string> log;
        private readonly int maxEvents;
        private readonly long maxBytes;
        private readonly object gate = new object();
        private readonly ConcurrentQueue<Dictionary<string, object>> queue = new ConcurrentQueue<Dictionary<string, object>>();
        private readonly AutoResetEvent wake = new AutoResetEvent(false);
        private EventLogWatcher watcher;
        private Thread writer;
        private volatile bool stopping;
        public volatile bool Done;
        private long observed, sent, dropped, errors, queuedBytes, peakBytes;
        private string stopReason = "requested";
        public readonly string RunId;
        public readonly string SampleHash;

        public Session(string run, string hash, int events, long bytes,
                       Action<Dictionary<string, object>> output, Action<string> logger)
        {
            RunId = run; SampleHash = hash; maxEvents = events; maxBytes = bytes; send = output; log = logger;
        }

        public void Start()
        {
            // No XPath filtering: keep all events admitted by the installed Sysmon configuration.
            var query = new EventLogQuery("Microsoft-Windows-Sysmon/Operational", PathType.LogName, "*");
            watcher = new EventLogWatcher(query, null, false);
            watcher.EventRecordWritten += OnEvent;
            watcher.Enabled = true;
            var ready = Wire.Message("ready", RunId);
            ready["sample_sha256"] = SampleHash;
            ready["guest_utc"] = Wire.Utc();
            ready["channel"] = "Microsoft-Windows-Sysmon/Operational";
            send(ready); // Callbacks only enqueue; READY always precedes event frames.
            StartWriter();
        }

        internal void StartWriter()
        {
            writer = new Thread(WriteLoop) { IsBackground = true, Name = "Sysmon serial sender" };
            writer.Start();
        }

        private void OnEvent(object sender, EventRecordWrittenEventArgs args)
        {
            if (args.EventException != null)
            {
                Interlocked.Increment(ref errors);
                log("Event subscription error: " + args.EventException.Message);
                return;
            }
            if (args.EventRecord == null) return;
            using (var record = args.EventRecord)
            {
                try { AcceptXml(record.ToXml()); }
                catch (Exception ex) { Interlocked.Increment(ref errors); log("Event render error: " + ex.Message); }
            }
        }

        // Separate queue admission makes ordering and overflow behavior testable without Sysmon.
        internal void AcceptXml(string xml)
        {
            lock (gate)
            {
                if (stopping) return;
                observed++;
                long bytes = (long)xml.Length * 2;
                if (xml.Length > 1024 * 1024 || queue.Count >= maxEvents || queuedBytes + bytes > maxBytes)
                {
                    dropped++;
                    return;
                }
                var message = Wire.Message("event", RunId);
                message["seq"] = observed;
                message["xml"] = xml;
                queue.Enqueue(message);
                queuedBytes += bytes;
                peakBytes = Math.Max(peakBytes, queuedBytes);
                wake.Set();
            }
        }

        private Dictionary<string, object> Stats(string type)
        {
            lock (gate)
            {
                var data = Wire.Message(type, RunId);
                data["guest_utc"] = Wire.Utc();
                data["observed"] = observed;
                data["sent"] = sent;
                data["dropped"] = dropped;
                data["watcher_errors"] = Interlocked.Read(ref errors);
                data["queued_events"] = queue.Count;
                data["queued_xml_bytes"] = queuedBytes;
                data["peak_queued_xml_bytes"] = peakBytes;
                data["reason"] = stopReason;
                return data;
            }
        }

        private void WriteLoop()
        {
            try
            {
                var heartbeat = System.Diagnostics.Stopwatch.StartNew();
                while (true)
                {
                    Dictionary<string, object> message;
                    if (queue.TryDequeue(out message))
                    {
                        lock (gate) { queuedBytes -= ((string)message["xml"]).Length * 2L; }
                        send(message);
                        Interlocked.Increment(ref sent);
                    }
                    else if (stopping) break;
                    else wake.WaitOne(50);
                    if (heartbeat.ElapsedMilliseconds >= 1000)
                    {
                        send(Stats("heartbeat"));
                        heartbeat.Restart();
                    }
                }
                send(Stats("end"));
            }
            catch (Exception ex) { log("Transport stopped: " + ex.Message); }
            finally { Done = true; }
        }

        public void Stop(string reason)
        {
            if (stopping) return;
            // Dispose outside gate: Windows may wait for a callback holding gate.
            if (watcher != null)
            {
                try { watcher.Enabled = false; watcher.Dispose(); }
                catch (Exception ex) { Interlocked.Increment(ref errors); log(ex.Message); }
                watcher = null;
            }
            lock (gate) { stopReason = reason; stopping = true; }
            wake.Set();
        }

        public void Dispose()
        {
            Stop("collector_exit");
            if (writer != null && writer.IsAlive) writer.Join(3000);
            // Do not dispose wake while a timed-out writer may still be using it.
            if (writer == null || !writer.IsAlive) wake.Dispose();
        }
    }

    internal static class Program
    {
        private static volatile bool exit;
        private static readonly object logGate = new object();
        private static string logPath;
        private static void Log(string value)
        {
            string line = Wire.Utc() + " " + value;
            Console.Error.WriteLine(line);
            if (String.IsNullOrEmpty(logPath)) return;
            lock (logGate)
            {
                try
                {
                    if (File.Exists(logPath) && new FileInfo(logPath).Length > 5 * 1024 * 1024)
                    {
                        File.Delete(logPath + ".old");
                        File.Move(logPath, logPath + ".old");
                    }
                    File.AppendAllText(logPath, line + Environment.NewLine, Encoding.UTF8);
                }
                catch { /* Logging must not stop collection. */ }
            }
        }

        private static Dictionary<string, string> Options(string[] args)
        {
            var options = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < args.Length; i += 2)
            {
                if (i + 1 >= args.Length || !Regex.IsMatch(args[i], "^--(port|baud|queue-events|queue-mib|log)$"))
                    throw new ArgumentException("Usage: SysmonSerialCollector.exe --port COM1 --baud 115200 --queue-events 8192 --queue-mib 64 [--log PATH]");
                options.Add(args[i], args[i + 1]);
            }
            return options;
        }

        private static string Get(Dictionary<string, string> options, string key, string fallback)
        { return options.ContainsKey(key) ? options[key] : fallback; }

        private static string Field(Dictionary<string, object> command, string key)
        { return command.ContainsKey(key) ? Convert.ToString(command[key], CultureInfo.InvariantCulture) : ""; }

        public static int Main(string[] args)
        {
            try
            {
                var options = Options(args);
                string portName = Get(options, "--port", "COM1");
                int baud = Int32.Parse(Get(options, "--baud", "115200"));
                int events = Int32.Parse(Get(options, "--queue-events", "8192"));
                int mib = Int32.Parse(Get(options, "--queue-mib", "64"));
                if (!Regex.IsMatch(portName, "^COM[1-9][0-9]*$", RegexOptions.IgnoreCase) || baud <= 0 ||
                    events < 1 || events > 1000000 || mib < 1 || mib > 1024) throw new ArgumentException("Invalid port/queue/baud options.");
                logPath = Get(options, "--log", "");
                if (logPath.Length > 0) Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(logPath)));
                Console.CancelKeyPress += delegate(object sender, ConsoleCancelEventArgs e) { e.Cancel = true; exit = true; };
                Log("Collector 1.0; port=" + portName + "; waiting for host START.");
                while (!exit)
                {
                    try { ServePort(portName, baud, events, mib); }
                    catch (Exception ex) { Log("Serial connection error: " + ex.Message); Thread.Sleep(2000); }
                }
                return 0;
            }
            catch (Exception ex) { Console.Error.WriteLine(ex.Message); return 1; }
        }

        private static void ServePort(string name, int baud, int events, int mib)
        {
            using (var port = new SerialPort(name, baud, Parity.None, 8, StopBits.One))
            {
                port.Encoding = new UTF8Encoding(false, true);
                port.Handshake = Handshake.None;
                port.ReadTimeout = 250;
                port.WriteTimeout = 2000;
                port.ReadBufferSize = 65536;
                port.WriteBufferSize = 65536;
                port.DtrEnable = true;
                port.RtsEnable = true;
                port.Open();
                object writeGate = new object();
                Action<Dictionary<string, object>> send = delegate(Dictionary<string, object> message)
                {
                    string frame = Wire.Encode(message);
                    lock (writeGate) { port.Write(frame); }
                };
                Session session = null;
                string buffer = "";
                var idle = System.Diagnostics.Stopwatch.StartNew();
                try
                {
                    while (!exit)
                    {
                        if (session != null && session.Done) { session.Dispose(); session = null; }
                        if (session == null && idle.ElapsedMilliseconds >= 2000)
                        {
                            var hello = Wire.Message("hello", "");
                            hello["collector_version"] = "1.0";
                            send(hello);
                            idle.Restart();
                        }
                        buffer += port.ReadExisting();
                        if (buffer.Length > 8192) throw new InvalidDataException("Control frame exceeds 8192 characters.");
                        int newline;
                        while ((newline = buffer.IndexOf('\n')) >= 0)
                        {
                            string line = buffer.Substring(0, newline).Trim();
                            buffer = buffer.Substring(newline + 1);
                            if (line.Length == 0) continue;
                            string run = "";
                            try
                            {
                                var command = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(line);
                                run = Field(command, "run_id");
                                if (Field(command, "v") != "1") throw new InvalidDataException("Unsupported protocol version.");
                                string type = Field(command, "type");
                                if (type == "start")
                                {
                                    string hash = Field(command, "sample_sha256").ToLowerInvariant();
                                    if (!Regex.IsMatch(run, "^[a-zA-Z0-9_-]{1,80}$") || !Regex.IsMatch(hash, "^[a-f0-9]{64}$"))
                                        throw new InvalidDataException("Invalid run_id/sample_sha256.");
                                    if (session != null) throw new InvalidOperationException("Session already active; STOP it or restart collector.");
                                    session = new Session(run, hash, events, mib * 1024L * 1024L, send, Log);
                                    try { session.Start(); }
                                    catch { session.Dispose(); session = null; throw; }
                                    Log("Started " + run + " sample=" + hash);
                                }
                                else if (type == "stop" && session != null && session.RunId == run)
                                { session.Stop("requested"); }
                                else throw new InvalidDataException("Unknown command or inactive run.");
                            }
                            catch (Exception ex)
                            {
                                Log("Control error: " + ex.Message);
                                var error = Wire.Message("error", run);
                                error["message"] = ex.Message;
                                send(error);
                            }
                        }
                        Thread.Sleep(10);
                    }
                }
                finally { if (session != null) session.Dispose(); }
            }
        }
    }
}
