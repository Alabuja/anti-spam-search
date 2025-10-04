using AntiSpam.Services;
using Microsoft.AspNetCore.Builder;
using AntiSpam.Application.Services;
using AspNetCoreRateLimit;
using System.Text.Json.Serialization;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

var logger = LogService.ConfigireSerilog();
builder.Services.AddLogging(lb => lb.ClearProviders().AddSerilog(logger));

builder.Services.AddControllersWithViews(options => { options.SuppressAsyncSuffixInActionNames = false; })
        .AddJsonOptions(options => options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));

// IronOCR doesn't require any special path configuration
// It comes with embedded language data
var ocrEngine = builder.Configuration.GetValue<string>("Ocr:Engine") ?? "none";
Console.WriteLine($"OCR Engine configured: {ocrEngine}");

builder.Services.AddMemoryCache();
builder.Services.AddSpamAwareRateLimiting();
builder.Services.AddBusinessDependencies(builder.Configuration);
builder.Services.AddSwaggerServices();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.ConfigureSwagger(true);
app.UseHttpsRedirection();

// Enable serving static files from wwwroot
app.UseDefaultFiles();
app.UseStaticFiles();

app.UseIpRateLimiting();

app.UseAuthorization();
app.UseAuthentication();

app.MapControllers();

app.Run();
