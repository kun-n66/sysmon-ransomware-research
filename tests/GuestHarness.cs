// Test executable only: synthetic Sysmon-shaped events, no sample execution or Sysmon changes.
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using SysmonSerial;

internal static class GuestHarness
{
    private static string Xml(string hash, int id)
    {
        return "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"><System>" +
            "<Provider Name=\"Microsoft-Windows-Sysmon\"/><EventID>" + id + "</EventID>" +
            "<TimeCreated SystemTime=\"2026-09-07T00:00:00.1234567Z\"/><EventRecordID>123</EventRecordID></System>" +
            "<EventData><Data Name=\"Image\">C:\\samples\\test\\" + hash + ".exe</Data>" +
            "<Data Name=\"ProcessGuid\">{00000000-0000-0000-0000-000000000001}</Data>" +
            "<Data Name=\"CommandLine\">测试 &amp; &lt;escaped&gt; \"quoted\"</Data></EventData></Event>";
    }

    public static int Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        // vmrun stand-in for controller tests: record operations and signal a fake launch only.
        // No process is launched and no VM is touched by this branch.
        if (args.Length > 2 && args[0] == "-T")
        {
            string trigger = Environment.GetEnvironmentVariable("SYSMON_TEST_TRIGGER");
            string operations = Environment.GetEnvironmentVariable("SYSMON_TEST_OPERATIONS");
            if (String.IsNullOrEmpty(trigger) || String.IsNullOrEmpty(operations)) return 90;
            string operation = args[2] == "-gu" ? args[6] : args[2];
            File.AppendAllText(operations, operation + "\n");
            if (operation == "runProgramInGuest" && Environment.GetEnvironmentVariable("SYSMON_TEST_PROBE_FAILURE") == "1")
            {
                Console.Error.WriteLine("Synthetic guest authentication failure; secret=test-only");
                return 42;
            }
            if (operation == "runProgramInGuest" && Regex.IsMatch(args[args.Length - 1], @"[a-f0-9]{64}\.exe$"))
                File.WriteAllText(trigger, "synthetic launch");
            return 0;
        }
        if (args.Length > 0 && args[0] == "echo")
        {
            var values = new string[args.Length - 1];
            Array.Copy(args, 1, values, 0, values.Length);
            Console.Write(new JavaScriptSerializer().Serialize(values));
            return 0;
        }
        if (args.Length == 1 && args[0] == "sleep") { Thread.Sleep(10000); return 0; }
        if (args.Length == 1 && args[0] == "queue")
        {
            var messages = new List<Dictionary<string, object>>();
            using (var session = new Session("test", new string('a',64), 2, 1024 * 1024,
                   delegate(Dictionary<string, object> value) { messages.Add(value); }, Console.Error.WriteLine))
            {
                for (int i = 0; i < 3; i++) session.AcceptXml(Xml(new string('a',64), 11));
                session.Stop("test");
                session.StartWriter();
                for (int i = 0; i < 100 && !session.Done; i++) Thread.Sleep(20);
                if (!session.Done || messages.Count != 3) return 1;
                var end = messages[2];
                if ((long)end["observed"] != 3 || (long)end["sent"] != 2 || (long)end["dropped"] != 1) return 2;
                foreach (var message in messages) Console.Write(Wire.Encode(message));
            }
            return 0;
        }
        if (args.Length < 1) return 3;
        using (var pipe = new NamedPipeServerStream(args[0], PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
                                                   PipeOptions.Asynchronous, 65536, 65536))
        {
            Console.WriteLine("LISTENING");
            Console.Out.Flush();
            pipe.WaitForConnection();
            var reader = new StreamReader(pipe, new UTF8Encoding(false));
            var output = new StreamWriter(pipe, new UTF8Encoding(false)) { AutoFlush = true };
            var start = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(reader.ReadLine());
            string run = (string)start["run_id"];
            string hash = (string)start["sample_sha256"];
            Action<Dictionary<string, object>> send = delegate(Dictionary<string, object> message) { output.Write(Wire.Encode(message)); };
            var ready = Wire.Message("ready", run);
            ready["sample_sha256"] = hash;
            ready["guest_utc"] = Wire.Utc();
            send(ready);
            using (var session = new Session(run, hash, 100, 1024 * 1024, send, Console.Error.WriteLine))
            {
                session.AcceptXml(Xml(hash, 11)); // Preserve a prelaunch event.
                session.StartWriter();
                if (args.Length > 2 && args[1] == "gated")
                {
                    int tries = 0;
                    while (!File.Exists(args[2]) && tries++ < 1500) Thread.Sleep(20);
                    if (!File.Exists(args[2])) return 91;
                }
                session.AcceptXml(Xml(hash, 1));
                session.AcceptXml(Xml(hash, 22));
                if (args.Length > 1 && args[1] == "disconnect")
                {
                    Thread.Sleep(200);
                    pipe.Disconnect();
                    return 0;
                }
                string line;
                while ((line = reader.ReadLine()) != null)
                {
                    var command = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(line);
                    if ((string)command["type"] == "stop") break;
                }
                session.Stop("requested");
                for (int i = 0; i < 500 && !session.Done; i++) Thread.Sleep(20);
                if (!session.Done) return 4;
                Thread.Sleep(100);
            }
        }
        return 0;
    }
}
