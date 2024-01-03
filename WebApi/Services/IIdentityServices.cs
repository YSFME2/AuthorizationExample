using WebApi.Models.Dtos;
using WebApi.Models.Requests;
using WebApi.Models.Responses;

namespace WebApi.Services
{
    public interface IIdentityServices
    {
        Task<AuthenticationResultDto> Registration(RegistrationRequest request);
        Task<AuthenticationResultDto> Login(LoginRequest request);
        Task<AuthenticationResultDto> RefreshToken(string refreshToken);
        Task<bool> RevokeRefreshToken(string refreshToken);
        Task<AssignRoleResultResponse> AssignRole(AssignRoleRequest request);
    }
}
