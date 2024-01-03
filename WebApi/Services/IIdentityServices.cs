using WebApi.Models.Dtos;
using WebApi.Models.Requests;
using WebApi.Models.Responses;

namespace WebApi.Services
{
    public interface IIdentityServices
    {
        Task<RegistrationResultDto> Registration(RegistrationRequest request);
        Task<LoginResultDto> Login(LoginRequest request);
        Task<AssignRoleResultResponse> AssignRole(AssignRoleRequest request);
    }
}
