using AntiSpam.Application.Dtos;
using AntiSpam.Application.Enums;
using AntiSpam.Application.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Caching.Memory;
using System.Net.Mime;
using static AntiSpam.Application.Services.RateLimitingExtensions;

namespace AntiSpam.Controllers
{
    [ApiController]
    [Route("api/v1/[controller]")]
    [ApiVersion("1.0")]
    public class AnalyzeController : ControllerBase
    {
        private readonly ITextAnalyzer _textAnalyzer;
        private readonly IImageAnalyzer _imageAnalyzer;
        private readonly IBehaviorAnalyzer _behaviorAnalyzer;
        private readonly ISpamScoringService _scoringService;

        public AnalyzeController(ITextAnalyzer text, IImageAnalyzer image, IBehaviorAnalyzer behavior, ISpamScoringService scorer)
        {
            _textAnalyzer = text;
            _imageAnalyzer = image;
            _behaviorAnalyzer = behavior;
            _scoringService = scorer;
        }

        [HttpPost("text")]
        [EnableRateLimiting(PolicyPerUser)]
        public async Task<ActionResult<TextAnalysisResult>> AnalyzeText([FromBody] TextAnalysisInput input, CancellationToken ct)
        {
            return Ok(await _textAnalyzer.AnalyzeAsync(input, ct));
        }

        [HttpPost("image")]
        [Consumes(MediaTypeNames.Multipart.FormData)]
        [ProducesResponseType(typeof(ImageAnalysisResult), StatusCodes.Status200OK)]
        [EnableRateLimiting(PolicyPerUser)]
        public async Task<ActionResult<ImageAnalysisResult>> AnalyzeImage(IFormFile formFile, CancellationToken ct)
        {
            if (formFile is null || formFile.Length == 0)
                return BadRequest(new { error = "No image file provided or empty file." });

            await using var ms = new MemoryStream();
            await formFile.CopyToAsync(ms, ct);
            var bytes = ms.ToArray();

            var mainMime = formFile.ContentType;

            var result = await _imageAnalyzer.AnalyzeAsync(new ImageAnalysisInput(bytes, null, mainMime), ct);
            return Ok(result);
        }

        [HttpPost("behavior")]
        [EnableRateLimiting(PolicyPerUser)]
        public async Task<ActionResult<BehaviorAnalysisResult>> AnalyzeBehavior([FromBody] BehaviorAnalysisInput input, CancellationToken ct)
        {
            return Ok(await _behaviorAnalyzer.AnalyzeAsync(input, ct));
        }
             
        [HttpPost("score")]
        [EnableRateLimiting(PolicyPerUserTight)]
        public async Task<ActionResult<SpamDecision>> Score([FromBody] CombinedAnalyzeRequest req, CancellationToken ct)
        {
            TextAnalysisResult? t = null;
            ImageAnalysisResult? i = null;
            BehaviorAnalysisResult? b = null;

            if (!string.IsNullOrWhiteSpace(req.Text))
                t = await _textAnalyzer.AnalyzeAsync(new TextAnalysisInput(req.Text!), ct);

            if (!string.IsNullOrWhiteSpace(req.ImageBase64))
                i = await _imageAnalyzer.AnalyzeAsync(new ImageAnalysisInput(Convert.FromBase64String(req.ImageBase64!), req.ImageOcrText, req.ImageMimeType), ct);

            if (req.Events is not null && req.Events.Count > 0)
                b = await _behaviorAnalyzer.AnalyzeAsync(new BehaviorAnalysisInput(req.UserId, req.Events, TimeSpan.FromHours(req.LookbackHours)), ct);

            var decision = await _scoringService.ScoreAsync(new SpamEvidence(t, i, b), ct);

            ElevateRiskIfNeeded(HttpContext, decision);

            return Ok(decision);
        }

        private static void ElevateRiskIfNeeded(HttpContext ctx, SpamDecision decision)
        {
            if (decision.Verdict == SpamVerdict.Allow) return;

            var cache = ctx.RequestServices.GetRequiredService<IMemoryCache>();
            var userId = ctx.Request.Headers["X-User-Id"].FirstOrDefault()
                         ?? ctx.User?.FindFirst("sub")?.Value
                         ?? ctx.Connection.RemoteIpAddress?.ToString()
                         ?? "unknown";

            var key = $"risk:user:{userId}";
            var risk = cache.GetOrCreate(key, e =>
            {
                e.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(30);
                return 0;
            });

            risk += decision.Verdict == SpamVerdict.Block ? 2 : 1;
            cache.Set(key, risk, TimeSpan.FromMinutes(30));
        }
    }
}
