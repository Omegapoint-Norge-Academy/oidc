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
        var user = new UserInfo()
        {
            IsAuthenticated = User.Identity?.IsAuthenticated ?? false,
            Claims = User.Claims.ToDictionary(c => c.Type, c => c.Value),
        };

        return Ok(user);
    }
}