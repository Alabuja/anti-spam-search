using Serilog;
using Serilog.Core;

namespace AntiSpam.Services
{
    public static class LogService
    {
        public static Logger ConfigireSerilog()
        {
            return new LoggerConfiguration()
                    .WriteTo.Console()
                    .WriteTo.File("log/txt/deliver_services.log", rollingInterval: RollingInterval.Day)
                    .Filter.ByExcluding("RequestPath like '/health%'")
                    .Filter.ByExcluding("RequestPath like '/metric%'")
                    .Filter.ByExcluding("RequestPath like '/swagger%'")
                    .CreateLogger();
        }
    }
}
