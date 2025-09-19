using KVM_ERP.Models;
using ClubMembership.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Routing;

namespace KVM_ERP
{
  
    public class MenuNavData
    {
        private readonly ApplicationDbContext context = new ApplicationDbContext();
        public IEnumerable<MenuNavbar> navbarItems()
        {
            //" + Session["CUSRID"] + "
            //var uname = HttpSessionStateBase["CUSRID"].ToString();
            var amenu = new List<MenuNavbar>();

            //var query = context.Database.SqlQuery<MenuRoleMaster>("selecgit statust * from MenuRoleMaster where Roles='admin'");
            var query = context.Database.SqlQuery<MenuRoleMaster>("select * from MenuRoleMaster where Roles='" + System.Web.HttpContext.Current.Session["CUSRID"].ToString() + "'");
            foreach (var data in query)
            {
                amenu.Add(new MenuNavbar { MenuGId = Convert.ToInt32(data.MenuGId),
                                           MenuGIndex = Convert.ToInt32(data.MenuGIndex),
                                           LinkText  = data.LinkText,
                                           ActionName = data.ActionName,
                                           ControllerName = data.ControllerName,
                                           username = System.Web.HttpContext.Current.Session["CUSRID"].ToString(),// "admin",
                                           imageClass = data.ImageClassName, estatus = true });
            }

            return amenu.ToList();
        }

        public IEnumerable<User> users()
        {
            var users = new List<User>();

            var query = context.Database.SqlQuery<AspNetUser>("select * from AspNetUsers");
            foreach (var data1 in query)
            {
                users.Add(new User
                {
                    Id = data1.Id,
                    user = data1.UserName,
                    password = data1.PasswordHash,
                    estatus = true,
                    RememberMe = true
                });
            }
            return users.ToList();
        }

        public IEnumerable<Roles> roles()
        {
            var roles = new List<Roles>();
            roles.Add(new Roles { rowid = 1, idUser = 1, idMenu = 1, status = true });
            roles.Add(new Roles { rowid = 2, idUser = 1, idMenu = 2, status = true });
            roles.Add(new Roles { rowid = 3, idUser = 1, idMenu = 3, status = true });
            roles.Add(new Roles { rowid = 4, idUser = 1, idMenu = 4, status = true });
            roles.Add(new Roles { rowid = 5, idUser = 1, idMenu = 5, status = true });
            roles.Add(new Roles { rowid = 6, idUser = 1, idMenu = 6, status = true });
            roles.Add(new Roles { rowid = 7, idUser = 1, idMenu = 7, status = true });
            roles.Add(new Roles { rowid = 8, idUser = 2, idMenu = 1, status = true });
            roles.Add(new Roles { rowid = 9, idUser = 2, idMenu = 2, status = true });
            roles.Add(new Roles { rowid = 10, idUser = 2, idMenu = 3, status = true });
            roles.Add(new Roles { rowid = 11, idUser = 2, idMenu = 4, status = true });
            roles.Add(new Roles { rowid = 12, idUser = 2, idMenu = 5, status = true });
            roles.Add(new Roles { rowid = 13, idUser = 3, idMenu = 1, status = true });
            roles.Add(new Roles { rowid = 14, idUser = 3, idMenu = 2, status = true });

            return roles.ToList();
        }

        public IEnumerable<MenuNavbar> itemsPerUser(string controller, string action, string userName)
        {
            
            IEnumerable<MenuNavbar> items = navbarItems();
            //IEnumerable<Roles> rolesNav = roles();
            IEnumerable<User> usersNav = users();

            var navbar =  items.Where(p => p.ControllerName == controller && p.action == action).Select(c => { c.activeli = "active"; return c; }).ToList();

            navbar = (from nav in items
                      where nav.username == userName

                      select new MenuNavbar
                      {
                          MenuGId = nav.MenuGId,
                          MenuGIndex = nav.MenuGIndex,
                          LinkText = nav.LinkText,
                          ControllerName = nav.ControllerName,
                          ActionName = nav.ActionName,
                          imageClass = nav.imageClass,
                          estatus = nav.estatus,
                          activeli = nav.activeli
                      }).ToList();

            return navbar.ToList();
        }

    }
}