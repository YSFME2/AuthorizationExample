using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using WebApi.Models.Requests;
using WebApi.Services;

namespace WebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        private readonly IIdentityServices _identityServices;

        public IdentityController(IIdentityServices identityServices)
        {
            _identityServices = identityServices;
        }

        [HttpPost]
        public async Task<IActionResult> Register(RegistrationRequest request)
        {
            var result = await _identityServices.Registration(request);
            return result.IsSuccess ? Ok(result.Authentication!) : BadRequest(result.Errors);
        }


        [HttpPost]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            var result = await _identityServices.Login(request);
            return result.IsSuccess ? Ok(result.Authentication!) : BadRequest(result.Errors);
        }
    }
}
