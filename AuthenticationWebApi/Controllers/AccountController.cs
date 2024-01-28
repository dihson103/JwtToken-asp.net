using JwtAuthenticationManager;
using JwtAuthenticationManager.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthenticationWebApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private readonly JwtTokenHandler _jwtTokenHandler;

        public AccountController(JwtTokenHandler jwtTokenHandler)
        {
            _jwtTokenHandler = jwtTokenHandler;
        }

        [HttpPost]
        public IActionResult Authenticate([FromBody] AuthenticationRequest authenticationRequest)
        {
            var authenticatinResponse = _jwtTokenHandler.GenerateJwtToken(authenticationRequest);

            if(authenticatinResponse == null)
            {
                return Unauthorized();
            }

            return Ok(authenticatinResponse);
        }
    }
}
