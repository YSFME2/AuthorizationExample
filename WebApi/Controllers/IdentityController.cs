using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WebApi.Models.Requests;
using WebApi.Services;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Produces("application/json")]
    public class IdentityController : ControllerBase
    {
        private readonly IIdentityServices _identityServices;

        public IdentityController(IIdentityServices identityServices)
        {
            _identityServices = identityServices;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register(RegistrationRequest request)
        {
            var result = await _identityServices.Registration(request);
            if (result.IsSuccess)
                AppendRefreshToken(result.Authentication!.RefreshToken, result.Authentication.RefreshTokenExpiration);
            return result.IsSuccess ? Ok(result.Authentication!) : BadRequest(result.Errors);
        }



        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            var result = await _identityServices.Login(request);
            if (result.IsSuccess)
                AppendRefreshToken(result.Authentication!.RefreshToken, result.Authentication.RefreshTokenExpiration);
            return result.IsSuccess ? Ok(result.Authentication!) : BadRequest(result.Errors);
        }

        [HttpPost("AssignToRole")]
        public async Task<IActionResult> AssignToRole(AssignRoleRequest request)
        {
            var result = await _identityServices.AssignRole(request);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }


        [HttpGet("RefreshToken")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["RT"];
            var result = await _identityServices.RefreshToken(refreshToken);
            if (result.IsSuccess)
                AppendRefreshToken(result.Authentication!.RefreshToken, result.Authentication.RefreshTokenExpiration);
            return result.IsSuccess ? Ok(result.Authentication) : BadRequest(result.Errors);
        }

        [HttpPost("RevokeRefreshToken")]
        public async Task<IActionResult> RevokeRefreshToken(Request<string> request = null)
        {
            var refreshToken = request?.Data ?? Request.Cookies["RT"];

            return await _identityServices.RevokeRefreshToken(refreshToken) ? Ok() : BadRequest();
        }

        private void AppendRefreshToken(string refreshToken, DateTime expiration)
        {
            Response.Cookies.Append("RT", refreshToken, new CookieOptions { Expires = expiration });
        }


    }
}
