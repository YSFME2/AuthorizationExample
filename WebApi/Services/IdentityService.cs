using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using NuGet.Packaging;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using WebApi.Models;
using WebApi.Models.Dtos;
using WebApi.Models.Requests;
using WebApi.Models.Responses;
using WebApi.Settings;

namespace WebApi.Services
{
    public class IdentityService : IIdentityServices
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly JwtSettings _jwtSettings;
        private readonly RoleManager<IdentityRole> _roleManager;

        public IdentityService(JwtSettings jwtSettings, UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _jwtSettings = jwtSettings;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        public async Task<AssignRoleResultResponse> AssignRole(AssignRoleRequest request)
        {
            var user = await _userManager.FindByIdAsync(request.UserId);
            if (user == null || !await _roleManager.RoleExistsAsync(request.Role))
                return new() { Errors = ["User Id or Role is invalid!"] };

            await _userManager.AddToRoleAsync(user, request.Role);
            return new AssignRoleResultResponse { IsSuccess = true };
        }

        public async Task<LoginResultDto> Login(LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                return new LoginResultDto
                {
                    Errors = [new() { Code = "UserCredentials", Description = "User not Exist or wrong credentials" }]
                };
            }
            return new LoginResultDto
            {
                IsSuccess = true,
                Authentication = await GenerateToken(user)
            };
        }

        public async Task<RegistrationResultDto> Registration(RegistrationRequest request)
        {
            var x = _jwtSettings.Secret;
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser is not null)
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

            await _userManager.AddToRoleAsync(appUser, "User");

            return new RegistrationResultDto
            {
                IsSuccess = true,
                Authentication = await GenerateToken(appUser)
            };
        }

        private async Task<AuthenticationResponse> GenerateToken(AppUser appUser)
        {
            var claims = await _userManager.GetClaimsAsync(appUser);
            var roles = await _userManager.GetRolesAsync(appUser);

            foreach (var role in roles)
                claims.Add(new Claim("roles", role));

            claims.AddRange([
                new(JwtRegisteredClaimNames.Sub, appUser.UserName),
                new(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Email , appUser.Email),
                new(JwtRegisteredClaimNames.Name,appUser.FullName),
                new("uid",appUser.Id)
                ]);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Secret));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var expiration = DateTime.Now.AddDays(_jwtSettings.ExpirationInDaies);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: expiration,
                signingCredentials: signingCredentials);

            return new AuthenticationResponse
            {
                Email = appUser.Email,
                Expiration = expiration,
                FullName = appUser.FullName,
                Roles = roles.ToList(),
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken)
            };
        }
    }
}
