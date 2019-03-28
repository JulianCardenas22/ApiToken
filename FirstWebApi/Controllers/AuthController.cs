using FirstWebApi.ViewModels;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace FirstWebApi.Controllers
{
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterViewModel model)
        {
            var user = new IdentityUser
            {
                UserName = model.Username,
                Email = model.Username,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, "Customer");
            }
            else
            {
                return Unauthorized();
            }


            return Created("Created", new { Username = user.UserName });
        }


        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(model.Username);
                if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                {
                    var claim = new[]
                    {
                    new Claim(JwtRegisteredClaimNames.Sub,model.Username)
                };
                    var a = _configuration["Jwt:SigninKey"];
                    var signinKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(a));
                    var tokenExpiryInMinutes = Convert.ToUInt32(_configuration["Jwt:TokenExpiryInMinutes"]);

                    var token = new JwtSecurityToken(
                        issuer: _configuration["Jwt:Site"],
                        claims: new List<Claim>(),
                        audience: _configuration["Jwt:Site"],
                        expires: DateTime.Now.AddMinutes(tokenExpiryInMinutes),
                        signingCredentials: new SigningCredentials(signinKey, SecurityAlgorithms.HmacSha256));

                    var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                    return Ok(new { Token = tokenString, TokenExpiricy = token.ValidTo });
                };

                return Unauthorized();
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
      

           
        }



    }
}
