using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController:BaseApiController
    {
        private readonly DataContext _dataContext;
        private readonly ITokenService _tokenService;

        public AccountController(DataContext dataContext , ITokenService tokenService)
        {
            _dataContext = dataContext;
            _tokenService = tokenService;
        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {

            if (await UserExists(registerDto.Username)) return BadRequest("UserName Is Taken !!! ");

                using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            _dataContext.Users.Add(user);

            await _dataContext.SaveChangesAsync();

            return new UserDto{
                username=user.UserName ,
                Token= _tokenService.CreateToken(user)
            };
        }


        private async Task<bool> UserExists(string username)
        {
            return await _dataContext.Users.AnyAsync(x => x.UserName == username.ToLower());
        }

        
        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
          var user= await _dataContext.Users.SingleOrDefaultAsync(x=>x.UserName==loginDto.Username);

          if(user==null) return Unauthorized("Invalid UserName !!! ");

          using var hmac = new HMACSHA512(user.PasswordSalt);

          var computeHash=hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

         for (int i = 0; i < computeHash.Length; i++)
         {
             if(computeHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password !!! ");
         }

          return new UserDto{
                username=user.UserName ,
                Token= _tokenService.CreateToken(user)
            };
        }

    }

}