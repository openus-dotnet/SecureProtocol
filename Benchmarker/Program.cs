using System.Text.Json;

internal class Program
{
    private class Log
    {
        public required string Type { get; set; }
        public required int Size { get; set; }
        public required int Repeat {  get; set; }
        public required float Average { get; set; }
    }

    private static void Main(string[] args)
    {
        List<Log> logs = new List<Log>();

        using (StreamReader sr = new StreamReader(args[0]))
        {
            while (sr.EndOfStream == false)
            {
                string json = sr.ReadLine()!;
                Log? log = JsonSerializer.Deserialize<Log>(json);

                if (log != null)
                {
                    logs.Add(log);
                }
            }
        }

        logs = logs
            .GroupBy(log => new { log.Type, log.Size, log.Repeat })
            .Select(group => new Log
            {
                Type = group.Key.Type,
                Size = group.Key.Size,
                Repeat = group.Key.Repeat,
                Average = group.Average(log => log.Average)
            })
            .ToList();

        foreach (Log log in logs)
        {
            Console.WriteLine(JsonSerializer.Serialize(log));
        }

        
    }
}