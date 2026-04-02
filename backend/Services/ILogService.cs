using System.Threading.Tasks;

namespace backend.Services
{
    public interface ILogService
    {
        Task LogAsync(string level, string source, string message, object? data = null);
        Task LogInfoAsync(string source, string message, object? data = null);
        Task LogErrorAsync(string source, string message, object? data = null);
    }
}
