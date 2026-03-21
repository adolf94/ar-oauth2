using System;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
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
            
            // Construct the content for Cloud Receive push
            var content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                { "to", email },
                { "secret", secret },
                { "device", device },
                { "payload", payloadJson }
            });

            _logger.LogInformation("Pushing data to Llamalabs Automate Cloud Receive for user: {Email}, device: {Device}", email, device);

            try
            {
                // Create a cancellation token for timeout (e.g., 10 seconds)
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));

                // Documentation says it should be a POST request with form-urlencoded content.
                var response = await _httpClient.PostAsync("https://llamalab.com/automate/cloud/message", content, cts.Token);
                
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Llamalabs Automate Cloud Receive message sent successfully.");
                    return true;
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync(cts.Token);
                    _logger.LogError("Llamalabs Automate Cloud Receive failed. Status: {StatusCode}, Error: {Error}", response.StatusCode, errorContent);
                    return false;
                }
            }
            catch (OperationCanceledException)
            {
                _logger.LogWarning("Llamalabs Automate push request timed out after 10 seconds.");
                return false;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while sending Llamalabs Automate Cloud Receive message.");
                return false;
            }
        }
    }
}
