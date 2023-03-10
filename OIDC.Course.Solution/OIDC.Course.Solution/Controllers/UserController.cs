using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace OIDC.Course.Solution.Controllers;

[ApiController]
[Route("client/[controller]")]
public class UserController : ControllerBase
{
    [HttpGet]
    [ProducesResponseType(typeof(UserInfo), StatusCodes.Status200OK)]
    [AllowAnonymous]
    public IActionResult GetCurrentUser()
    {
        var claimsToExpose = new List<string>()
        {
            "name"
        };

        var user = new UserInfo(
            User.Identity?.IsAuthenticated ?? false,
            User.Claims
                .Select(c => new KeyValuePair<string, string>(c.Type, c.Value))
                .Where(c => claimsToExpose.Contains(c.Key))
                .ToList());
        return Ok(user);
    }
}