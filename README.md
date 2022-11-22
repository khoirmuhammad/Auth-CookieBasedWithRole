# Cookie Based Authentication With Role
This source code is more intermediate level than "Cookie Based Authentication" in https://github.com/khoirmuhammad/Auth-CookieBasedStandard. Analogy : Once we get authenticated to enter a building. Then we will have limitation to access the floor or even particular room.

#### Scenario
- Application's Role consist of "Admin" & "User"
- Application's Method / Resource consist of "GetClaimsUserOnly" only can be accessed by User, "GetClaimsAdminOnly" only can be accessed by Admin, "GetClaims" both of roles able to access

1. Create Role Class in order to set role constants

```
public class Role
{
    public const string User = "User";
    public const string Admin = "Admin";
    public const string AdminUser = "Admin,User";
}
```
2. Create User Class in order to store user data in memory instead of using database

```
public class User
{
    public string Username { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
}
```

3. Only need this attribute to implement authorization on each action method. Once we have logged in, Roles attribute will be automatically have a role value, since we set role's value in claims

```
var claims = new List<Claim>
{
    new Claim(ClaimTypes.Name, user.Username),
    new Claim(ClaimTypes.Role, user.Role)
};
```
Add this attribute on each action method as necessary
```
[Authorize(Roles = Role.User)]
[Authorize(Roles = Role.Admin)]
[Authorize(Roles = Role.AdminUser)]
```

4. In service configuration (Startup.cs / Program.cs), we need to set this below code
```
options.Events.OnRedirectToAccessDenied = (context) =>
{
  context.Response.StatusCode = 403;
  return Task.CompletedTask;
};
```

Why? Users are not authorization (even if they're authenticated) will not allowed to access resource that doesn't set to them. By default ASP Net core will redirect to "Account/AccessDenied" path. In case we don't provide the controller and action method, then API will recognized as HTTP 404. It will confusing us, why it's 404, it should be 403 (Method Not Allowed)
