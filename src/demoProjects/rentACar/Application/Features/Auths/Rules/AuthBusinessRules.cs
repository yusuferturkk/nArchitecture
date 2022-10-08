using Application.Services.Repositories;
using Core.CrossCuttingConcerns.Exceptions;
using Core.Security.Entities;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Application.Features.Auths.Rules
{
    public class AuthBusinessRules
    {
        private readonly IUserRepository _repository;

        public AuthBusinessRules(IUserRepository repository)
        {
            _repository = repository;
        }

        public async Task EmailCanNotBeDuplicatedWhenRegistered(string email)
        {
            User? user = await _repository.GetAsync(u => u.Email == email);
            if (user != null) throw new BusinessException("Mail already exists.");
        }
    }
}
