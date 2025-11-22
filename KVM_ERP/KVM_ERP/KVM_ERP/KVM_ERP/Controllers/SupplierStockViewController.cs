using System;
using System.Linq;
using System.Web.Mvc;
using KVM_ERP.Models;

namespace KVM_ERP.Controllers
{
    public class SupplierStockViewController : Controller
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: SupplierStockView
        [Authorize(Roles = "SupplierStockViewIndex")]
        public ActionResult Index()
        {
            ViewBag.Title = "Supplier wise Stock View";
            return View();
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
