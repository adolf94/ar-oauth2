using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace backend.Services
{
    public class LlamalabsService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<LlamalabsService> _logger;

        public LlamalabsService(HttpClient httpClient, ILogger<LlamalabsService> logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        public async Task<bool> SendCloudReceiveAsync(string email, string secret, string device, object payload)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(device))
            {
                _logger.LogWarning("Missing required parameters for Automate Cloud Receive. Email: {Email}, Secret: {Secret}, Device: {Device}", 
                    email, string.IsNullOrEmpty(secret) ? "Empty" : "Set", device);
                return false;
            }

            // Automate Cloud Receive expects payload as a string or JSON. 
            // We'll send it as a JSON string.
            var payloadJson = JsonSerializer.Serialize(payload);
            
            // Construct the URL for Cloud Receive push
            var url = $"https://llamalab.com/automate/cloud/message?to={Uri.EscapeDataString(email)}&secret={Uri.EscapeDataString(secret)}&device={Uri.EscapeDataString(device)}&payload={Uri.EscapeDataString(payloadJson)}";

            _logger.LogInformation("Pushing data to Llamalabs Automate Cloud Receive for user: {Email}, device: {Device}", email, device);

            try
            {
                // Note: Documentation says it should be a POST request.
                var response = await _httpClient.PostAsync(url, null);
                
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Llamalabs Automate Cloud Receive message sent successfully.");
                    return true;
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    _logger.LogError("Llamalabs Automate Cloud Receive failed. Status: {StatusCode}, Error: {Error}", response.StatusCode, errorContent);
                    return false;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while sending Llamalabs Automate Cloud Receive message.");
                return false;
            }
        }
    }
}
