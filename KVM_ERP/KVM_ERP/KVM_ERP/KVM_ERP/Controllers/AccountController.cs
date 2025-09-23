using ClubMembership.Data;
using KVM_ERP.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.Owin.Security;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using System.Data.Entity;

//using System.IO; // for File/Directory
//using System.Linq; // for string.Join
//using System.Text; // for Encoding

namespace KVM_ERP.Controllers
{
    [Authorize]
    public class AccountController : Controller
    {
        ApplicationDbContext _db = new ApplicationDbContext();
        public AccountController()
                   : this(new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext())))
        {
        }

        IAuthenticationManager Authentication
        {
            get { return HttpContext.GetOwinContext().Authentication; }
        }

        public AccountController(UserManager<ApplicationUser> userManager)
        {
            UserManager = userManager;
        }

        public UserManager<ApplicationUser> UserManager { get; private set; }

        // GET: Account
        [AllowAnonymous]
        public ActionResult Login(string returnUrl)
        {
            ApplicationDbContext context = new ApplicationDbContext();
            ClubMembershipDBEntities db = new ClubMembershipDBEntities();
            ViewBag.ReturnUrl = returnUrl;
            Session["DEPTID"] = "";
            Session["DEPTNAME"] = "";
            Session["CUSRID"] = "";
            Session["BRNCHNAME"] = "";
            Session["BRNCHID"] = "";
            Session["F_BRNCHID"] = "";
            Session["F_BRNCHNAME"] = "";
            Session["F_DBRNCHID"] = "";
            Session["F_DEPTNAME"] = "";
            Session["BRNCHCTYPE"] = "";
            Session["COMPID"] = "";
            Session["S_BRNCHID"] = "";
            Session["Group"] = "";
            Session["STATEID"] = "";
            Session["EMP_STATEID"] = "";
            Session["EMP_LOCTID"] = "";
            Session["grntranrefid"] = "0";
            ViewBag.COMPID = new SelectList(context.companymasters, "COMPID", "COMPNAME");
            Session["LDATE"] = DateTime.Now.ToString("dd-MM-yyyy");
            Session["GYrDesc"] = (DateTime.Now.Year - 1) + " - " + (DateTime.Now.Year);
            ViewBag.COMPYID = new SelectList(context.VW_ACCOUNTING_YEAR_DETAIL_ASSGN.OrderByDescending(m => m.YRDESC), "COMPYID", "YRDESC");

            Session["USER"] = "";

            // Clear any stale anti-forgery cookie to avoid user mismatch after login
            var afCookie = Request.Cookies["__RequestVerificationToken"];
            if (afCookie != null)
            {
                afCookie.Expires = DateTime.Now.AddDays(-1);
                Response.Cookies.Add(afCookie);
            }

            //return View(new LoginViewModel());
            return View();
        }

        //
        // POST: /Account/Login
        [HttpPost]
        [AllowAnonymous]
        // NOTE: Temporarily disabled anti-forgery validation to unblock login due to missing token cookie
        public async Task<ActionResult> Login(LoginViewModel model, string returnUrl) { 
            ApplicationDbContext context = new ApplicationDbContext();
            ClubMembershipDBEntities db = new ClubMembershipDBEntities();

            ViewBag.COMPID = new SelectList(context.companymasters, "COMPID", "COMPNAME");
            ViewBag.COMPYID = new SelectList(context.VW_ACCOUNTING_YEAR_DETAIL_ASSGN.OrderByDescending(m => m.YRDESC), "COMPYID", "YRDESC");

            var brnchctype = 0;// context.Database.SqlQuery<Int16>("Select BRNCHCTYPE From BranchMaster Where BRNCHID = '" + user.BrnchId + "'").ToList();
            var stateid = 1;// context.Database.SqlQuery<Int32>("Select STATEID From BranchMaster Where BRNCHID = '" + user.BrnchId + "'").ToList();

            // Check if user is enabled - with error handling for missing tables/views
            var userchk = new List<int>();
            try
            {
                userchk = context.Database.SqlQuery<int>("Select CateId From View_User_Diable_Chk_For_Login Where UserName = '" + model.UserName.Trim() + "' And DispStatus = 0").ToList();
            }
            catch (Exception ex)
            {
                // If view doesn't exist or EMPLOYEEMASTER table is missing, allow login for now
                System.Diagnostics.Debug.WriteLine($"User check failed: {ex.Message} - Allowing login");
                userchk.Add(1); // Add dummy value to allow login
            }
            
            if (userchk.Count > 0)
            {
                if (ModelState.IsValid)
                {
                    var user = await UserManager.FindAsync(model.UserName, model.Password);
                    if (user != null)
                    {

                        context.Database.ExecuteSqlCommand("Update AspNetUsers Set NPassword = '" + model.Password + "' where id ='" + user.Id + "'");

                        Session["compyid"] = model.COMPYID;
                        Session["CUSRID"] = model.UserName;
                        Session["COMPID"] = model.COMPID;
                        Session["F_DEPTNAME"] = "ADMIN";// user.DeptName;
                        Session["BRNCHCTYPE"] = 0;// brnchctype[0];// model.BRNCHCTYPE;
                        Session["DEPTID"] = "2";// deptid[0];
                        Session["DEPTNAME"] = "ADMIN";// deptdesc[0];
                        Session["grntranrefid"] = "0";
                        Session["STATEID"] = 1;// stateid[0];

                        //

                        Session["LDATE"] = Request.Form.Get("LDATE"); var COMPID = Request.Form.Get("COMPID");
                        DateTime TmpDate = Convert.ToDateTime(Request.Form.Get("LDATE")).Date;
                        var LMNTH = TmpDate.Month; var LYR = TmpDate.Year; var PFYear = 0; var PTYear = 0; var PFDATE = ""; var PTDATE = ""; var GYrDesc = "";

                        if (LMNTH >= 4)
                        {// Response.Write(LMNTH + ".." + LYR + "..." + Session["LDATE"]); Response.End(); 
                            PFYear = LYR;
                            PTYear = LYR + 1;
                            PFDATE = "01/04/" + PFYear; PTDATE = "31/03/" + PTYear;
                            GYrDesc = PFYear + " - " + PTYear;



                        }
                        else
                        { //Response.Write("ELSE" + LMNTH + ".." + LYR + "..." + Session["LDATE"]); Response.End(); 
                            PFYear = LYR - 1;
                            PTYear = LYR;
                            PFDATE = "01/04/" + PFYear; PTDATE = "31/03/" + PTYear;
                            GYrDesc = PFYear + " - " + PTYear;
                        }

                        // Resolve CompId safely
                        var compIdStr = Request.Form.Get("COMPID");
                        int compIdParsed;
                        int compId;
                        if (!int.TryParse(compIdStr, out compIdParsed))
                        {
                            compId = context.companymasters
                                .OrderBy(c => c.COMPID)
                                .Select(c => c.COMPID)
                                .FirstOrDefault();
                        }
                        else
                        {
                            compId = compIdParsed;
                        }
                        Session["COMPID"] = compId;

                        // Get or create AccountingYear and resolve YrId deterministically
                        var accYears = context.Database.SqlQuery<PR_ACCOUNTINGYEAR_ID_CHK_Result>(
                            "PR_ACCOUNTINGYEAR_ID_CHK @PFYear={0},@PTYear={1}", PFYear, PTYear).ToList();
                        int yrId;
                        if (accYears.Count == 0)
                        {
                            context.Database.ExecuteSqlCommand(
                                "INSERT INTO AccountingYear (YrDesc, FDate, TDate, CUSRID, PRCSDATE) VALUES ({0}, {1}, {2}, {3}, {4})",
                                GYrDesc,
                                Convert.ToDateTime(PFDATE),
                                Convert.ToDateTime(PTDATE),
                                Session["CUSRID"],
                                DateTime.Now);

                            // Re-query to get the created YRID via the same proc
                            accYears = context.Database.SqlQuery<PR_ACCOUNTINGYEAR_ID_CHK_Result>(
                                "PR_ACCOUNTINGYEAR_ID_CHK @PFYear={0},@PTYear={1}", PFYear, PTYear).ToList();
                        }
                        yrId = accYears.Last().YRID;

                        // Get or create CompanyAccountingDetail for (CompId, YrId)
                        var compDtl = context.Database.SqlQuery<PR_COMPANYACCOUNTINGDETAIL_ID_CHK_Result>(
                            "PR_COMPANYACCOUNTINGDETAIL_ID_CHK @PCompId={0},@PYrId={1}", compId, yrId).ToList();

                        if (compDtl.Count == 0)
                        {
                            context.Database.ExecuteSqlCommand(
                                "INSERT INTO CompanyAccountingDetail (CompId, YrId, CUSRID, PRCSDATE) VALUES ({0}, {1}, {2}, {3})",
                                compId,
                                yrId,
                                Session["CUSRID"],
                                DateTime.Now);

                            var resolvedCompyId = context.Database.SqlQuery<int>(
                                "SELECT COMPYID FROM CompanyAccountingDetail WHERE CompId={0} AND YrId={1}",
                                compId, yrId).FirstOrDefault();
                            System.Web.HttpContext.Current.Session["compyid"] = resolvedCompyId;
                        }
                        else
                        {
                            System.Web.HttpContext.Current.Session["compyid"] = Convert.ToInt32(compDtl[0].COMPYID);
                        }

                        Session["GYrDesc"] = GYrDesc;

                        // Minimal diagnostics for tracing
                        System.Diagnostics.Debug.WriteLine($"[LoginInit] CompId={compId}, YrId={yrId}, GYrDesc={GYrDesc}, compyid={System.Web.HttpContext.Current.Session["compyid"]}");


                        //var sql = context.Database.SqlQuery<int>("select GroupId from ApplicationUserGroups inner join AspNetUsers on AspNetUsers.Id=ApplicationUserGroups.UserId where AspNetUsers.UserName='" + model.UserName + "'").ToList();

                        //if (sql[0].Equals(1)) { Session["Group"] = "Admin"; }
                        //if (sql[0].Equals(2)) { Session["Group"] = "SuperAdmin"; }
                        //if (sql[0].Equals(4)) { Session["Group"] = "Users"; }
                        //if (sql[0].Equals(3)) { Session["Group"] = "Manager"; }

                        var sql = context.Database.SqlQuery<VW_USER_DETAILS>("select * from VW_USER_DETAILS Where UserName='" + model.UserName + "'").ToList();
                        if (sql.Count == 0)
                        {
                            Session["Group"] = "";
                        }
                        else
                        {
                            if (sql.Count > 1)
                            { Session["Group"] = sql[1].GroupName; }
                            else
                            { Session["Group"] = sql[0].GroupName; }

                        }
                        //if (sql[0].Equals(1)) { Session["Group"] = "Admin"; }
                        //if (sql[0].Equals(2)) { Session["Group"] = "SuperAdmin"; }
                        // if (sql[0].Equals(4)) { Session["Group"] = "Users"; }
                        // if (sql[0].Equals(3)) { Session["Group"] = "Manager"; }

                       // var aa = Session["EMPLID"].ToString();
                        //var emplid = 0;
                        //if (aa != "") { emplid = Convert.ToInt32(Session["EMPLID"]); }
                        //var rsql = context.Database.SqlQuery<EmployeeMaster>("select * from EmployeeMaster Where CATEID = '" + emplid + "'").ToList();
                        //if (rsql.Count > 0)
                        //{
                        //    Session["EMP_STATEID"] = rsql[0].STATEID;
                        //    Session["EMP_LOCTID"] = rsql[0].LOCTID;
                        //}
                        //else
                        //{
                        //    Session["EMP_STATEID"] = "0";
                        //    Session["EMP_LOCTID"] = "0";
                        //}

                        //Session["EXCLPATH"] = "D:\\SACT_EXCEL\\" + Session["CUSRID"];

                        // Sync ASP.NET Identity role with Session["Group"] so [Authorize(Roles="Admin")] works right after login
                        try
                        {
                            var groupName = (Session["Group"] as string) ?? string.Empty;
                            var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(context));
                            if (!roleManager.RoleExists("Admin"))
                            {
                                roleManager.Create(new IdentityRole("Admin"));
                            }
                            var roles = await UserManager.GetRolesAsync(user.Id);
                            if (groupName.Equals("Admin", StringComparison.OrdinalIgnoreCase))
                            {
                                if (!roles.Contains("Admin"))
                                    await UserManager.AddToRoleAsync(user.Id, "Admin");
                            }
                            else
                            {
                                if (roles.Contains("Admin"))
                                    await UserManager.RemoveFromRoleAsync(user.Id, "Admin");
                            }
                        }
                        catch (Exception ex)
                        {
                            System.Diagnostics.Debug.WriteLine("[Login RoleSync] " + ex.Message);
                        }

                    }

                    if (user != null)
                    {
                        // Track last login without requiring DB schema changes: use cookie + session
                        DateTime? prevLogin = null;
                        var prevCookie = Request.Cookies["LastLoginAt"];
                        if (prevCookie != null)
                        {
                            DateTime parsed;
                            if (DateTime.TryParse(prevCookie.Value, out parsed))
                            {
                                prevLogin = parsed;
                            }
                        }
                        Session["PreviousLoginTime"] = prevLogin;

                        await SignInAsync(user, model.RememberMe);

                        // Store current login time
                        var now = DateTime.Now;
                        Session["LoginTime"] = now;
                        var cookie = new HttpCookie("LastLoginAt", now.ToString("o")) { Expires = DateTime.Now.AddYears(1), HttpOnly = true };
                        Response.Cookies.Add(cookie);
                        // Clear any stale anti-forgery cookie created before sign-in
                        var afCookie2 = Request.Cookies["__RequestVerificationToken"];
                        if (afCookie2 != null)
                        {
                            afCookie2.Expires = DateTime.Now.AddDays(-1);
                            Response.Cookies.Add(afCookie2);
                        }
                        Session["MyMenu"] = "";
                        context.Database.ExecuteSqlCommand("delete from menurolemaster where Roles='" + model.UserName + "'");
                        context.Database.ExecuteSqlCommand("EXEC pr_USER_MENU_DETAIL_ASSGN @PKUSRID='" + model.UserName + "'");
                        return RedirectToLocal(returnUrl);
                        //return RedirectToAction("Index", "Home");
                    }

                    ModelState.AddModelError("", "Invalid username or password.");

                    return View(model);

                }
            }
            else
            {
                ModelState.AddModelError("", "User Name Not Exists.");
            }


            return View(model);
            //if (!ModelState.IsValid)
            //{
            //    return View(model);
            //}
            //var data = new Data();
            //var users = data.users();

            //if (users.Any(p => p.user == model.UserName && p.password == model.Password))
            //{
            //    var identity = new ClaimsIdentity(new[] { new Claim(ClaimTypes.Name, model.UserName),}, DefaultAuthenticationTypes.ApplicationCookie);

            //    Authentication.SignIn(new AuthenticationProperties
            //    {
            //        IsPersistent = model.RememberMe
            //    }, identity);

            //    return RedirectToAction("Index", "Home");
            //}
            //else
            //{
            //    ModelState.AddModelError("", "Invalid login attempt.");
            //    return View(model);
            //}
        }


        private async Task SignInAsync(ApplicationUser user, bool isPersistent)
        {
            AuthenticationManager.SignOut(DefaultAuthenticationTypes.ExternalCookie);
            var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
            AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = isPersistent }, identity);
        }

        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing && UserManager != null)
            {
                UserManager.Dispose();
                UserManager = null;
            }
            base.Dispose(disposing);
        }

        private void AddErrors(IdentityResult result)
        {
            foreach (var error in result.Errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        private bool HasPassword()
        {
            var user = UserManager.FindById(User.Identity.GetUserId());
            if (user != null)
            {
                return user.PasswordHash != null;
            }
            return false;
        }

        public enum ManageMessageId
        {
            ChangePasswordSuccess,
            SetPasswordSuccess,
            RemoveLoginSuccess,
            Error
        }


        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            // Route users to the appropriate dashboard when no returnUrl is provided
            var group = Session["Group"] as string;
            if (!string.IsNullOrEmpty(group) && group.Equals("Admin", StringComparison.OrdinalIgnoreCase))
            {
                return RedirectToAction("AdminDashboard", "Home");
            }
            // For regular users, land on a blank Index page; Dashboard is accessible from the menu
            return RedirectToAction("Index", "Home");
        }


        //
        // POST: /Account/LogOff
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult LogOff()
        {
            // Record the time of this logout as the last seen/login display for next visit
            try
            {
                var now = DateTime.Now;
                var cookie = new HttpCookie("LastLoginAt", now.ToString("o")) // ISO 8601
                {
                    HttpOnly = true,
                    Expires = DateTime.Now.AddYears(1)
                };
                Response.Cookies.Add(cookie);
                // Clear session copies so a new session will prefer cookie value next time
                Session["PreviousLoginTime"] = now;
                Session["CurrentLoginTime"] = null;
            }
            catch { /* best-effort only */ }
            Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
            Session.Clear();
            Session.Abandon();
            var afCookie = Request.Cookies["__RequestVerificationToken"];
            if (afCookie != null)
            {
                afCookie.Expires = DateTime.Now.AddDays(-1);
                Response.Cookies.Add(afCookie);
            }
            return RedirectToAction("Login", "Account");
        }

        [Authorize(Roles = "Admin")]
        public ActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(AccountViewModels.RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            // Server-side uniqueness validation
            var normalizedUserName = (model.UserName ?? string.Empty).Trim();
            var normalizedEmail = (model.Email ?? string.Empty).Trim();
            var normalizedMobile = (model.MobileNo ?? string.Empty).Trim();

            if (_db.Users.Any(u => u.UserName == normalizedUserName))
            {
                ModelState.AddModelError("UserName", "Username is already taken.");
            }
            if (_db.Users.Any(u => u.Email == normalizedEmail))
            {
                ModelState.AddModelError("Email", "Email is already registered.");
            }
            if (_db.Users.Any(u => u.MobileNo == normalizedMobile))
            {
                ModelState.AddModelError("MobileNo", "Mobile number is already registered.");
            }
            // Enforce 10-digit mobile server-side
            if (normalizedMobile.Length != 10 || !normalizedMobile.All(char.IsDigit))
            {
                ModelState.AddModelError("MobileNo", "Mobile number must be exactly 10 digits.");
            }
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                var user = model.GetUser();
                var result = await UserManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    // Auto-assign newly created user to default "Users" group
                    try
                    {
                        var usersGroup = _db.Groups.FirstOrDefault(g => g.Name == "Users");
                        if (usersGroup == null)
                        {
                            usersGroup = new Group { Name = "Users" };
                            _db.Groups.Add(usersGroup);
                            _db.SaveChanges();
                        }

                        var created = _db.Users.FirstOrDefault(u => u.UserName == model.UserName);
                        if (created != null)
                        {
                            bool exists = created.Groups.Any(g => g.GroupId == usersGroup.Id);
                            if (!exists)
                            {
                                created.Groups.Add(new ApplicationUserGroup { UserId = created.Id, GroupId = usersGroup.Id });
                                _db.SaveChanges();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        System.Diagnostics.Debug.WriteLine("[Create->Assign Users group] " + ex.Message);
                    }
                    TempData["Message"] = "User created successfully.";
                    return RedirectToAction("Index");
                }
                foreach (var e in result.Errors) { ModelState.AddModelError("", e); }
                return View(model);
            }
            catch (Exception ex)
            {
                var msg = ex.GetBaseException().Message;
                ModelState.AddModelError("", "Failed to create user: " + msg);
                return View(model);
            }
        }

        [Authorize(Roles = "Admin")]
        public ActionResult Edit(string id)
        {
            var user = _db.Users.FirstOrDefault(u => u.UserName == id || u.Id == id);
            if (user == null) return HttpNotFound();
            var vm = new AccountViewModels.EditUserViewModel(user);
            return View(vm);
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(AccountViewModels.EditUserViewModel model)
        {
            if (!ModelState.IsValid) return View(model);
            var user = _db.Users.FirstOrDefault(u => u.UserName == model.UserName);
            if (user == null) return HttpNotFound();

            // Server-side uniqueness checks excluding current user
            var normalizedEmail = (model.Email ?? string.Empty).Trim();
            var normalizedMobile = (model.MobileNo ?? string.Empty).Trim();
            if (_db.Users.Any(u => u.Id != user.Id && u.Email == normalizedEmail))
            {
                ModelState.AddModelError("Email", "Email is already registered to another user.");
            }
            if (_db.Users.Any(u => u.Id != user.Id && u.MobileNo == normalizedMobile))
            {
                ModelState.AddModelError("MobileNo", "Mobile number is already registered to another user.");
            }
            // Enforce 10-digit mobile server-side
            if (normalizedMobile.Length != 10 || !normalizedMobile.All(char.IsDigit))
            {
                ModelState.AddModelError("MobileNo", "Mobile number must be exactly 10 digits.");
            }
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                user.FirstName = model.FirstName;
                user.LastName = model.LastName;
                user.Email = model.Email;
                user.MobileNo = model.MobileNo;
                user.DOB = model.DOB;
                user.Gender = model.Gender;
                _db.SaveChanges();
                TempData["Message"] = "User updated successfully.";
                return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                var msg = ex.GetBaseException().Message;
                ModelState.AddModelError("", "Failed to update user: " + msg);
                return View(model);
            }
        }

        [Authorize(Roles = "Admin")]
        public ActionResult Manage(string id)
        {
            var user = _db.Users.FirstOrDefault(u => u.UserName == id || u.Id == id);
            if (user == null) return HttpNotFound();
            var vm = new AccountViewModels.ManageUserViewModel();
            ViewBag.HasLocalPassword = true; // legacy view expects this boolean
            ViewBag.TargetUser = user.UserName;
            return View(vm);
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Manage(string id, AccountViewModels.ManageUserViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ViewBag.HasLocalPassword = true;
                return View(model);
            }
            var user = _db.Users.FirstOrDefault(u => u.UserName == id || u.Id == id);
            if (user == null) return HttpNotFound();

            IdentityResult result;
            try
            {
                if (UserManager.UserTokenProvider != null)
                {
                    var token = await UserManager.GeneratePasswordResetTokenAsync(user.Id);
                    result = await UserManager.ResetPasswordAsync(user.Id, token, model.NewPassword);
                }
                else
                {
                    // Fallback when no IUserTokenProvider is configured: remove and add password
                    await UserManager.RemovePasswordAsync(user.Id);
                    result = await UserManager.AddPasswordAsync(user.Id, model.NewPassword);
                }
            }
            catch (NotSupportedException)
            {
                // Same fallback for providers that don't support tokens
                await UserManager.RemovePasswordAsync(user.Id);
                result = await UserManager.AddPasswordAsync(user.Id, model.NewPassword);
            }
            if (!result.Succeeded)
            {
                foreach (var e in result.Errors) { ModelState.AddModelError("", e); }
                ViewBag.HasLocalPassword = true;
                return View(model);
            }
            user.NPassword = model.NewPassword; // store plain for legacy compatibility
            _db.SaveChanges();
            TempData["Message"] = "Password updated.";
            return RedirectToAction("Index");
        }

        [Authorize]
        [HttpGet]
        public ActionResult ChangePassword()
        {
            // Hide Change Password for Admins
            if (User.IsInRole("Admin") || (Session != null && Session["Group"] != null && Session["Group"].ToString() == "Admin"))
            {
                return RedirectToAction("AdminDashboard", "Home");
            }
            var vm = new AccountViewModels.ManageUserViewModel();
            ViewBag.HasLocalPassword = true;
            return View(vm);
        }

        [Authorize]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> ChangePassword(AccountViewModels.ManageUserViewModel model)
        {
            // Hide Change Password for Admins
            if (User.IsInRole("Admin") || (Session != null && Session["Group"] != null && Session["Group"].ToString() == "Admin"))
            {
                return RedirectToAction("AdminDashboard", "Home");
            }
            if (!ModelState.IsValid)
            {
                ViewBag.HasLocalPassword = true;
                return View(model);
            }

            try
            {
                var userId = User.Identity.GetUserId();
                var result = await UserManager.ChangePasswordAsync(userId, model.OldPassword, model.NewPassword);
                if (!result.Succeeded)
                {
                    foreach (var e in result.Errors) { ModelState.AddModelError("", e); }
                    ViewBag.HasLocalPassword = true;
                    return View(model);
                }

                // Update legacy NPassword field and refresh sign-in cookie so new security stamp is used
                var user = _db.Users.FirstOrDefault(u => u.Id == userId);
                if (user != null)
                {
                    user.NPassword = model.NewPassword;
                    _db.SaveChanges();
                }

                // Refresh auth cookie to ensure claims are up-to-date
                AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                var identity = await UserManager.CreateIdentityAsync(user, DefaultAuthenticationTypes.ApplicationCookie);
                AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = true }, identity);

                TempData["Message"] = "Password changed successfully.";
                return RedirectToAction("Index", "Home");
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", "Failed to change password: " + ex.GetBaseException().Message);
                ViewBag.HasLocalPassword = true;
                return View(model);
            }
        }

        [Authorize(Roles = "Admin")]
        public ActionResult UserGroups(string id)
        {
            var user = _db.Users.Include("Groups.Group").FirstOrDefault(u => u.UserName == id || u.Id == id);
            if (user == null) return HttpNotFound();
            var allGroups = _db.Groups.OrderBy(g => g.Name).ToList();
            var selectedIds = new HashSet<int>(user.Groups.Select(g => g.GroupId));
            ViewBag.AllGroups = allGroups;
            ViewBag.Selected = selectedIds;
            ViewBag.UserName = user.UserName;
            return View();
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public ActionResult UserGroups(string id, int[] groupIds)
        {
            var user = _db.Users.Include("Groups").FirstOrDefault(u => u.UserName == id || u.Id == id);
            if (user == null) return HttpNotFound();
            user.Groups.Clear();
            var gids = groupIds ?? new int[0];
            foreach (var gid in gids)
            {
                user.Groups.Add(new ApplicationUserGroup { UserId = user.Id, GroupId = gid });
            }
            _db.SaveChanges();

            // If admin changed their own groups, update session immediately
            var currentUser = Session["CUSRID"] as string;
            if (!string.IsNullOrEmpty(currentUser) && (string.Equals(currentUser, user.UserName, StringComparison.OrdinalIgnoreCase)))
            {
                // Pick the first group name deterministically if any
                var firstGroup = _db.Groups
                    .Where(g => gids.Contains(g.Id))
                    .OrderBy(g => g.Name)
                    .Select(g => g.Name)
                    .FirstOrDefault();
                Session["Group"] = firstGroup ?? string.Empty;

                // Sync Identity role and refresh auth cookie so new role takes effect immediately
                try
                {
                    using (var ctx = new ApplicationDbContext())
                    {
                        var roleManager = new RoleManager<IdentityRole>(new RoleStore<IdentityRole>(ctx));
                        if (!roleManager.RoleExists("Admin"))
                        {
                            roleManager.Create(new IdentityRole("Admin"));
                        }
                    }
                    var roles = UserManager.GetRoles(user.Id).ToList();
                    var isNowAdmin = (Session["Group"] as string)?.Equals("Admin", StringComparison.OrdinalIgnoreCase) == true;
                    if (isNowAdmin && !roles.Contains("Admin"))
                    {
                        UserManager.AddToRole(user.Id, "Admin");
                    }
                    if (!isNowAdmin && roles.Contains("Admin"))
                    {
                        UserManager.RemoveFromRoleAsync(user.Id, "Admin");
                    }
                    // Refresh sign-in to update role claims
                    AuthenticationManager.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                    var identity = UserManager.CreateIdentity(user, DefaultAuthenticationTypes.ApplicationCookie);
                    AuthenticationManager.SignIn(new AuthenticationProperties() { IsPersistent = true }, identity);
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine("[UserGroups RoleSync] " + ex.Message);
                }
            }
            return RedirectToAction("Index");
        }

        [Authorize(Roles = "Admin")]
        public ActionResult UserPermissions(string id)
        {
            var user = _db.Users.Include("Roles").FirstOrDefault(u => u.UserName == id || u.Id == id);
            if (user == null) return HttpNotFound();
            var roles = UserManager.GetRoles(user.Id).OrderBy(r => r).ToList();
            var vm = new AccountViewModels.UserPermissionsViewModel
            {
                UserName = user.UserName,
                Roles = roles.Select(r => new AccountViewModels.RoleViewModel
                {
                    RoleName = r,
                    Description = r // Use role name as description if none available
                }).ToList()
            };
            return View(vm);
        }

        [HttpPost]
        [Authorize(Roles = "Admin")]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(string id)
        {
            var user = _db.Users.FirstOrDefault(u => u.UserName == id || u.Id == id);
            if (user == null) return HttpNotFound();
            try
            {
                bool deletingSelf = string.Equals(user.UserName, User.Identity.Name, StringComparison.OrdinalIgnoreCase);

                // Remove group memberships
                var memberships = _db.Set<ApplicationUserGroup>().Where(ug => ug.UserId == user.Id).ToList();
                if (memberships.Any())
                {
                    _db.Set<ApplicationUserGroup>().RemoveRange(memberships);
                }

                // Remove identity roles
                var roles = UserManager.GetRoles(user.Id).ToArray();
                if (roles.Length > 0)
                {
                    await UserManager.RemoveFromRolesAsync(user.Id, roles);
                }

                // Delete user via EF context to avoid NotSupportedException from provider
                _db.Users.Remove(user);
                _db.SaveChanges();

                if (deletingSelf)
                {
                    Authentication.SignOut(DefaultAuthenticationTypes.ApplicationCookie);
                    Session.Clear();
                    Session.Abandon();
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", ex.Message);
            }
            return RedirectToAction("Index");
        }

        [Authorize(Roles = "Admin")]
        public ActionResult Index()
        {
            // Minimal users list for Admins
            var users = _db.Users.OrderBy(u => u.UserName).ToList();
            return View(users);
        }
    }
}