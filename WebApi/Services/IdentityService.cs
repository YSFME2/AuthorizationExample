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
using Microsoft.EntityFrameworkCore;

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

        public async Task<AuthenticationResultDto> Login(LoginRequest request)
        {
            var user = await _userManager.FindByEmailAsync(request.Email);
            if (user is null || !await _userManager.CheckPasswordAsync(user, request.Password))
            {
                return new AuthenticationResultDto
                {
                    Errors = [new() { Code = "UserCredentials", Description = "User not Exist or wrong credentials" }]
                };
            }
            return new AuthenticationResultDto
            {
                IsSuccess = true,
                Authentication = await GenerateToken(user)
            };
        }

        public async Task<AuthenticationResultDto> Registration(RegistrationRequest request)
        {
            var x = _jwtSettings.Secret;
            var existingUser = await _userManager.FindByEmailAsync(request.Email);
            if (existingUser is not null)
            {
                return new AuthenticationResultDto
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
                return new AuthenticationResultDto
                {
                    Errors = result.Errors.Select(error => new ErrorResponse() { Code = error.Code, Description = error.Description }).ToList(),
                };
            }

            await _userManager.AddToRoleAsync(appUser, "User");

            return new AuthenticationResultDto
            {
                IsSuccess = true,
                Authentication = await GenerateToken(appUser)
            };
        }

        public async Task<AuthenticationResultDto> RefreshToken(string refreshToken)
        {
            var result = new AuthenticationResultDto();
            var user = await _userManager.Users.SingleOrDefaultAsync(x => x.RefreshTokens.Any(t => t.Token == refreshToken));
            if(user == null)
            {
                result.Errors.Add(new ErrorResponse() { Code = "RefreshToken", Description = "Invalid or Expired Refresh Token" });
                return result;
            }

            var token = user.RefreshTokens.First(x => x.Token == refreshToken);
            if (!token.IsActive)
            {
                result.Errors.Add(new ErrorResponse() { Code = "RefreshToken", Description = "Invalid or Expired Refresh Token" });
                return result;
            }

            token.RevokedOn = DateTime.Now;
            await _userManager.UpdateAsync(user);

            result.IsSuccess = true;
            result.Authentication = await GenerateToken(user);
            return result;
        }

        public async Task<bool> RevokeRefreshToken(string refreshToken)
        {
            var user = await _userManager.Users.SingleOrDefaultAsync(x => x.RefreshTokens.Any(t => t.Token == refreshToken));
            if (user == null)
                return false;


            var token = user.RefreshTokens.First(x => x.Token == refreshToken);
            if (!token.IsActive)
                return true;

            token.RevokedOn = DateTime.Now;
            await _userManager.UpdateAsync(user);
            return true;
        }

        private async Task<AuthenticationResponse> GenerateToken(AppUser user)
        {
            var claims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);

            foreach (var role in roles)
                claims.Add(new Claim("roles", role));

            claims.AddRange([
                new(JwtRegisteredClaimNames.Sub, user.UserName),
                new(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()),
                new(JwtRegisteredClaimNames.Email , user.Email),
                new(JwtRegisteredClaimNames.Name,user.FullName),
                new("uid",user.Id)
                ]);

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_jwtSettings.Secret));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var expiration = DateTime.Now.AddDays(_jwtSettings.ExpirationInDays).AddMinutes(_jwtSettings.ExpirationInMinutes);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: expiration,
                signingCredentials: signingCredentials);

            var authenticationResponse =  new AuthenticationResponse
            {
                Email = user.Email,
                Expiration = expiration,
                FullName = user.FullName,
                Roles = roles.ToList(),
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken)
            };

            if (user.RefreshTokens.Any(x => x.IsActive))
            {
                var refreshToken = user.RefreshTokens.First(x => x.IsActive);
                refreshToken.ExpireOn = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpirationInDays);
                await _userManager.UpdateAsync(user);
                authenticationResponse.RefreshToken = refreshToken.Token;
                authenticationResponse.RefreshTokenExpiration = refreshToken.ExpireOn;
            }
            else
            {
                var refreshToken = GenerateRefreshToken(user.Id);
                user.RefreshTokens.Add(refreshToken);
                await _userManager.UpdateAsync(user);
                authenticationResponse.RefreshToken = refreshToken.Token;
                authenticationResponse.RefreshTokenExpiration = refreshToken.ExpireOn;
            }

            return authenticationResponse;
        }

        private RefreshToken GenerateRefreshToken(string userId)
        {
            return new RefreshToken()
            {
                Token = Convert.ToBase64String(Encoding.ASCII.GetBytes(userId += DateTime.UtcNow.Ticks.ToString() + Guid.NewGuid().ToString())),
                CreatedOn = DateTime.Now,
                ExpireOn = DateTime.Now.AddDays(_jwtSettings.RefreshTokenExpirationInDays),
            };
        }
    }
}
