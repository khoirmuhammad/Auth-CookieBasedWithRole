using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// Configure cookie based authentication
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(options =>
        {
            // Specify in case un-authenticated users
            options.Events.OnRedirectToLogin = (context) =>
            {
                context.Properties.IsPersistent = true;
                context.Response.StatusCode = 401;
                return Task.CompletedTask;
            };

            // Specify in case authenticated users, but have no authorization (user try to access admin method)
            // By default Net Core will redirect to Account/AccessDenied. If we don't have the resource then will return 404 in our API
            options.Events.OnRedirectToAccessDenied = (context) =>
            {
                context.Response.StatusCode = 403;
                return Task.CompletedTask;
            };

            // Specify the name of the auth cookie.
            // ASP.NET picks a dumb name by default. "AspNetCore.Cookies"
            options.Cookie.Name = "my_app_auth_cookie";
        });

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
