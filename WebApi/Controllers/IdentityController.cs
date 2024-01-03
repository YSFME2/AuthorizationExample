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
            return result.IsSuccess ? Ok(result.Authentication!) : BadRequest(result.Errors);
        }


        [HttpPost("Login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            var result = await _identityServices.Login(request);
            return result.IsSuccess ? Ok(result.Authentication!) : BadRequest(result.Errors);
        }

        [HttpPost("AssignToRole")]
        public async Task<IActionResult> AssignToRole(AssignRoleRequest request)
        {
            var result = await _identityServices.AssignRole(request);
            return result.IsSuccess ? Ok(result) : BadRequest(result);
        }
    }
}
