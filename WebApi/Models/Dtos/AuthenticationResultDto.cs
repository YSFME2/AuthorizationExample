using WebApi.Models.Responses;

namespace WebApi.Models.Dtos
{
    public class AuthenticationResultDto
    {
        public bool IsSuccess { get; set; }
        public List<ErrorResponse> Errors { get; set; } = new List<ErrorResponse>();
        public AuthenticationResponse? Authentication { get; set; }
    }
}
