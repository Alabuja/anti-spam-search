using AntiSpam.Application.Dtos;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSpam.Application.Services
{
    public static class DependencyService
    {
        public static void AddBusinessDependencies(this IServiceCollection services, IConfiguration? configuration = null)
        {
            var ocrOpts = new OcrOptions();
            configuration?.GetSection("Ocr")?.Bind(ocrOpts);
            services.AddSingleton(ocrOpts);

            if (ocrOpts.Engine.Equals("ironocr", StringComparison.OrdinalIgnoreCase))
                services.AddSingleton<IOcrService, IronOcrService>();
            else
                services.AddSingleton<IOcrService>(_ => new NoopOcrService());

            services.AddScoped<IBehaviorAnalyzer, BehaviorAnalyzer>();
            services.AddScoped<ITextAnalyzer, TextAnalyzer>();
            services.AddScoped<ISpamScoringService, DefaultSpamScoringService>();
            services.AddScoped<IImageAnalyzer, ImageAnalyzer>();
        }

        private sealed class NoopOcrService : IOcrService
        {
            public Task<string> ExtractTextAsync(byte[] imageBytes, CancellationToken ct = default)
                => Task.FromResult(string.Empty);
        }
    }
}
