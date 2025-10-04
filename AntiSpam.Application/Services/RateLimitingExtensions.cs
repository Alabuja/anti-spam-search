using AspNetCoreRateLimit;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.RateLimiting;
using System.Threading.Tasks;

namespace AntiSpam.Application.Services
{
    public static class RateLimitingExtensions
    {
        public const string PolicyPerUser = "PerUser";
        public const string PolicyPerUserTight = "PerUserTight"; // applied to /score
        public const string PolicyPerIp = "PerIp";
        public const string PolicyGlobal = "Global";

        public static IServiceCollection AddSpamAwareRateLimiting(this IServiceCollection services)
        {
            services.AddMemoryCache(); // used for dynamic tightening
            services.AddRateLimiter(options =>
            {
                options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

                options.OnRejected = async (ctx, token) =>
                {
                    // (optional) tell the client when to retry
                    ctx.HttpContext.Response.Headers.RetryAfter = "30";
                    if (ctx.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                    {
                        ctx.HttpContext.Response.Headers.RetryAfter = ((int)retryAfter.TotalSeconds).ToString();
                    }

                    await ctx.HttpContext.Response.WriteAsJsonAsync(new
                    {
                        error = "rate_limited",
                        detail = "Too many requests. Slow down and try again."
                    }, cancellationToken: token);
                };

                // Helper to pick a stable partition key
                static string PartitionKey(HttpContext httpContext)
                {
                    // Prefer your own notion of user (header/JWT). Fallback to IP.
                    var userId = httpContext.Request.Headers["X-User-Id"].FirstOrDefault()
                                 ?? httpContext.User?.FindFirst("sub")?.Value;

                    if (!string.IsNullOrWhiteSpace(userId))
                        return $"user:{userId}";

                    var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    return $"ip:{ip}";
                }

                // Per-user token bucket (typical usage)
                options.AddPolicy(PolicyPerUser, httpContext =>
                {
                    var key = PartitionKey(httpContext);

                    // Optional: dynamically adjust based on risk stored in IMemoryCache
                    var cache = httpContext.RequestServices.GetRequiredService<IMemoryCache>();
                    var risk = cache.GetOrCreate($"risk:{key}", e =>
                    {
                        e.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30);
                        return 0; // baseline "no extra risk"
                    });

                    // Base: 30 req/min with a burst of 15
                    // If risk elevated, tighten automatically.
                    var basePerMinute = risk >= 2 ? 12 : 30;          // refill tokens per minute
                    var burst = risk >= 2 ? 8 : 15;                   // bucket size

                    return RateLimitPartition.GetTokenBucketLimiter(key, _ => new TokenBucketRateLimiterOptions
                    {
                        TokenLimit = burst,
                        QueueLimit = 0,
                        ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                        TokensPerPeriod = basePerMinute,
                        AutoReplenishment = true
                    });
                });

                // A stricter per-user policy (attach to /score)
                options.AddPolicy(PolicyPerUserTight, httpContext =>
                {
                    var key = PartitionKey(httpContext);
                    return RateLimitPartition.GetTokenBucketLimiter(key, _ => new TokenBucketRateLimiterOptions
                    {
                        TokenLimit = 6,               // burst
                        QueueLimit = 0,
                        ReplenishmentPeriod = TimeSpan.FromMinutes(1),
                        TokensPerPeriod = 12,         // 12 req/min
                        AutoReplenishment = true
                    });
                });

                // Per-IP fixed window (coarse safety net)
                options.AddPolicy(PolicyPerIp, httpContext =>
                {
                    var ip = httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                    return RateLimitPartition.GetFixedWindowLimiter(ip, _ => new FixedWindowRateLimiterOptions
                    {
                        PermitLimit = 120,               // 120 req/min per IP
                        Window = TimeSpan.FromMinutes(1),
                        QueueLimit = 0
                    });
                });

                // Global concurrency cap (protects server under load)
                options.AddPolicy(PolicyGlobal, _ =>
                    RateLimitPartition.GetConcurrencyLimiter("global", _ => new ConcurrencyLimiterOptions
                    {
                        PermitLimit = 200,  // max concurrent requests across the app
                        QueueLimit = 0
                    })
                );
            });

            services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();
            services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
            services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
            services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();

            return services;
        }
    }
}
