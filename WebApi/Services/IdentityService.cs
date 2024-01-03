using Microsoft.AspNetCore.Identity;
using WebApi.Models;
using WebApi.Models.Dtos;
using WebApi.Models.Requests;
using WebApi.Models.Responses;

namespace WebApi.Services
{
    public class IdentityService : IIdentityServices
    {
        private readonly UserManager<AppUser> _userManager;

        public IdentityService(UserManager<AppUser> userManager)
        {
            _userManager = userManager;
        }
        public Task<LoginResultDto> Login(LoginRequest request)
        {
            throw new NotImplementedException();
        }

        public async Task<RegistrationResultDto> Registration(RegistrationRequest request)
        {
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser != null)
            {
                return new RegistrationResultDto
                {
                    Errors = [new() { Code = "", Description = "Email is already exist" }]
                };
            }

            var appUser = new AppUser
            {
                Email = request.Email,
                FullName = request.FullName,
                UserName = request.Email
            };

            var result = await _userManager.CreateAsync(appUser, request.Password.Trim());
            if (!result.Succeeded)
            {
                return new RegistrationResultDto
                {
                    Errors = result.Errors.Select(error => new ErrorResponse() { Code = error.Code, Description = error.Description }).ToList(),
                };
            }
            return new RegistrationResultDto
            {
                IsSuccess = true,
                Authentication =
            }
        }
    }
}
