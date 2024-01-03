namespace WebApi.Models.Responses
{
    public class AssignRoleResultResponse
    {
        public bool IsSuccess { get; set; }
        public List<string> Errors { get; set; }
    }
}
