using System;
using System.Threading.Tasks;
using backend.Data;
using backend.Models;
using Microsoft.Extensions.Logging;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Collections.Generic;
using System.Linq;
using Microsoft.EntityFrameworkCore;

namespace backend.Services
{
    public class LogService
    {
        private readonly AppDbContext _context;
        private readonly ILogger<LogService> _logger;

        public LogService(AppDbContext context, ILogger<LogService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task LogAsync(string level, string source, string message, object? data = null)
        {
            try
            {
                JsonNode? jsonData = null;
                if (data != null)
                {
                    if (data is string strData)
                    {
                        try { jsonData = JsonNode.Parse(strData); }
                        catch { jsonData = JsonValue.Create(strData); }
                    }
                    else if (data is JsonNode node)
                    {
                        jsonData = node;
                    }
                    else
                    {
                        jsonData = JsonSerializer.SerializeToNode(data);
                    }
                }

                var logEntry = new LogEntry
                {
                    Level = level,
                    Source = source,
                    Message = message,
                    Data = jsonData?.ToJsonString()
                };

                _context.Logs.Add(logEntry);
                await _context.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                // Fallback to internal logger if CosmosDB logging fails
                _logger.LogError(ex, "Failed to write log entry to CosmosDB: {Source} - {Message}", source, message);
            }
        }

        public async Task LogInfoAsync(string source, string message, object? data = null)
            => await LogAsync("Information", source, message, data);

        public async Task LogErrorAsync(string source, string message, object? data = null)
            => await LogAsync("Error", source, message, data);

    }
}
