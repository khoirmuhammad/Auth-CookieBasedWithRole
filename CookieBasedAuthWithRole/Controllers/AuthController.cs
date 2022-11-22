using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace CookieBaseAuthWithRole.Controllers
{
    public class User
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Role { get; set; } = string.Empty;
    }

    public class Role
    {
        public const string User = "User";
        public const string Admin = "Admin";
        public const string AdminUser = "Admin,User";
    }

    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly List<User> _users = new List<User>();

        public AuthController()
        {
            _users.Add(new User
            {
                Username = "admin",
                Password = "admin",
                Role = "Admin"
            });

            _users.Add(new User
            {
                Username = "user",
                Password = "user",
                Role = "User"
            });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login(string username, string password)
        {
            bool isAuth = _users.Where(w => w.Username == username && w.Password == password).Any();

            if (!isAuth)
                return Unauthorized();

            var user = _users.Where(w => w.Username == username && w.Password == password).First();

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var claimsIdentity = new ClaimsIdentity(
                claims, CookieAuthenticationDefaults.AuthenticationScheme);

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity));

            return Ok();
        }

        [Authorize(Roles = Role.User)]
        [HttpGet]
        [Route("GetClaimsUserOnly")]
        public IActionResult GetClaimsUserOnly()
        {
            string? username = HttpContext.User.Identity?.Name;

            return Ok($"{username} User Only");
        }

        [Authorize(Roles = Role.Admin)]
        [HttpGet]
        [Route("GetClaimsAdminOnly")]
        public IActionResult GetClaimsAdminOnly()
        {
            string? username = HttpContext.User.Identity?.Name;

            return Ok($"{username} Admin Only");
        }

        [Authorize(Roles = Role.AdminUser)]
        [HttpGet]
        [Route("GetClaims")]
        public IActionResult GetClaims()
        {
            string? username = HttpContext.User.Identity?.Name;

            return Ok($"{username} Both Admin & User");
        }

        [Authorize(Roles = Role.AdminUser)]
        [HttpPost]
        [Route("Logout")]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

            return Ok();
        }
    }

}
