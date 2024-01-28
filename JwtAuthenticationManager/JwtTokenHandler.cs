using JwtAuthenticationManager.Models;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthenticationManager
{
    public class JwtTokenHandler
    {
        public const string JWT_SECURITY_KEY = "NguyenDinhSon";
        public const int JWT_TOKEN_VALIDITY_MINS = 20;
        private readonly List<UserAccount> _users;

        public JwtTokenHandler()
        {
            _users = new List<UserAccount>()
            {
                new UserAccount
                {
                    UserName = "admin",
                    Password = "admin",
                    Role = "admin"
                },
                new UserAccount
                {
                    UserName = "user",
                    Password = "user",
                    Role = "user"
                }
            };
        }

        public AuthenticationResponse? GenerateJwtToken(AuthenticationRequest authenticationRequest)
        {
            if (string.IsNullOrEmpty(authenticationRequest.UserName) || string.IsNullOrEmpty(authenticationRequest.Password))
            {
                return null;
            }

            var user = _users.SingleOrDefault(u => u.UserName == authenticationRequest.UserName && u.Password == authenticationRequest.Password);
            if (user == null)
            {
                return null;
            }

            try
            {
                // Generate a secure random key
                var key = new byte[32];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(key);
                }

                var tokenExpiryTimeStamp = DateTime.UtcNow.AddMinutes(JWT_TOKEN_VALIDITY_MINS);

                var signingCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256);

                var claimsIdentity = new ClaimsIdentity(new List<Claim>
                {
                    new Claim(JwtRegisteredClaimNames.Name, authenticationRequest.UserName),
                    new Claim(ClaimTypes.Role, user.Role)
                });

                var securityTokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = claimsIdentity,
                    Expires = tokenExpiryTimeStamp,
                    SigningCredentials = signingCredentials
                };

                var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
                var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
                var token = jwtSecurityTokenHandler.WriteToken(securityToken);

                return new AuthenticationResponse
                {
                    UserName = user.UserName,
                    ExpiresIn = (int)tokenExpiryTimeStamp.Subtract(DateTime.UtcNow).TotalSeconds,
                    JwtToken = token
                };
            }
            catch (Exception ex)
            {
                // Log the exception
                Console.WriteLine($"Exception during JWT token generation: {ex.Message}");
                return null;
            }
        }


    }
}
