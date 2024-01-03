using WebApi.Models.Responses;

namespace WebApi.Models.Dtos
{
    public class RegistrationResultDto
    {
        public bool IsSuccess { get; set; }
        public List<ErrorResponse> Errors { get; set; }
        public AuthenticationResponse? Authentication { get; set; }
    }
}
