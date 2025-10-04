using Microsoft.OpenApi.Models;
using System.Reflection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Versioning;

namespace AntiSpam.Services
{
    public static class SwaggerService
    {
        public const string API_VERSION = "v1";

        /// <summary>
        /// Register Swagger Dependency to DI
        /// </summary>
        /// <param name="services"></param>
        public static void AddSwaggerServices(this IServiceCollection services)
        {
            //Add API versioning configuration
            services.AddApiVersioning(opt =>
            {
                opt.DefaultApiVersion = new ApiVersion(1, 0);
                opt.AssumeDefaultVersionWhenUnspecified = true;
                opt.ReportApiVersions = true;
                opt.ApiVersionReader = ApiVersionReader.Combine(
                    new UrlSegmentApiVersionReader(),
                                                                new HeaderApiVersionReader("x-api-version"),
                                                                new MediaTypeApiVersionReader("x-api-version"));
            });

            // Anti Spam more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            services.AddEndpointsApiExplorer();
            services.AddSwaggerGen(c =>
            {
                c.ResolveConflictingActions(x => x.First());
                c.SwaggerDoc(API_VERSION, new OpenApiInfo { Title = "AntiSpam API", Version = API_VERSION });
                #region XMl Documentation
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                c.IncludeXmlComments(xmlPath);
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = @"JWT Authorization header using the Bearer scheme. \r\n\r\n
                                Enter 'Bearer' [space] and then your token in the text input below.
                                \r\n\r\nExample: 'Bearer 12345abcdef'",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement()
                    {
                            {
                                new OpenApiSecurityScheme
                                {
                                    Reference = new OpenApiReference
                                    {
                                        Type = ReferenceType.SecurityScheme,
                                        Id = "Bearer"
                                    },
                                    Scheme = "oauth2",
                                    Name = "Bearer",
                                    In = ParameterLocation.Header,

                                },
                                new List<string>()
                            }
                    });
                #endregion
            });

        }

        /// <summary>
        /// Configure the swagger service on the pipeline
        /// </summary>
        /// <param name="app"></param>
        /// <param name="useSwagger"></param>
        public static void ConfigureSwagger(this IApplicationBuilder app, bool useSwagger = true)
        {
            if (useSwagger)
            {
                app.UseSwagger();
                app.UseSwaggerUI(c =>
                {
                    c.SwaggerEndpoint($"/swagger/{API_VERSION}/swagger.json", $"AntiSpam API {API_VERSION}");
                    c.RoutePrefix = "swagger";
                });
            }
        }
    }
}
