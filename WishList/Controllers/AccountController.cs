using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WishList.Models;
using WishList.Models.AccountViewModels;

namespace WishList.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        public IActionResult Register(RegisterViewModel registerViewModel)
        {
            if (!ModelState.IsValid)
            {
                return View(registerViewModel);
            }

            var result =  _userManager.CreateAsync(new ApplicationUser()
            {
                Email = registerViewModel.Email,
                UserName = registerViewModel.Email
            }, registerViewModel.Password);

            if (!result.Result.Succeeded)
            {
                foreach (var identityError in result.Result.Errors)
                {
                    ModelState.AddModelError(identityError.Code, identityError.Description);
                }

                return View(registerViewModel);
            }

            return RedirectToAction("Index", "Home");
        }


        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult Login(LoginViewModel loginViewModel)
        {
            if (!ModelState.IsValid)
            {
                return View(loginViewModel);
            }

            var result = _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password, false, false);

            if (!result.Result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, "Invalid login attempt.");

                return View(loginViewModel);
            }

            return RedirectToAction("Index", "Item");
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public IActionResult Logout()
        {
            _signInManager.SignOutAsync();
            return RedirectToAction("Index", "Home");
        }
    }
}
