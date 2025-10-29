using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using KVM_ERP.Models;

namespace KVM_ERP.Controllers
{
    [SessionExpire]
    public class RawMaterialInvoiceController : Controller
    {
        ApplicationDbContext context = new ApplicationDbContext();

        // GET: RawMaterialInvoice
        public ActionResult Index()
        {
            try
            {
                var invoices = context.Database.SqlQuery<RawMaterialInvoiceViewModel>(
                    @"SELECT TRANMID, TRANDATE, TRANNO, TRANDNO, TRANREFNO, CATENAME, TRANNAMT
                      FROM TRANSACTIONMASTER
                      ORDER BY TRANDATE DESC, TRANNO DESC"
                ).ToList();
                
                return View(invoices);
            }
            catch (Exception ex)
            {
                return Content($"Error loading invoices: {ex.Message}");
            }
        }

        public JsonResult GetAjaxData(JQueryDataTableParamModel param)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine("GetAjaxData called for Raw Material Invoice DataTables");
                
                // Get invoice data from TRANSACTIONMASTER
                var invoices = context.Database.SqlQuery<RawMaterialInvoiceViewModel>(
                    @"SELECT TRANMID, TRANDATE, TRANNO, TRANDNO, TRANREFNO, CATENAME, TRANNAMT
                      FROM TRANSACTIONMASTER
                      ORDER BY TRANDATE DESC, TRANNO DESC"
                ).ToList();

                // Format data for DataTables
                var allInvoices = invoices.Select(i => new {
                    TRANMID = i.TRANMID,
                    TRANDATE = i.TRANDATE.ToString("dd-MMM-yyyy"),
                    TRANNO = i.TRANNO,
                    TRANDNO = i.TRANDNO ?? "0000",
                    TRANREFNO = i.TRANREFNO ?? "-",
                    CATENAME = i.CATENAME ?? "",
                    TRANNAMT = i.TRANNAMT
                }).ToList();

                return Json(new { aaData = allInvoices }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in GetAjaxData: {ex.Message}");
                return Json(new { error = "Error loading data: " + ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }
    }

    // ViewModel for Raw Material Invoice display
    public class RawMaterialInvoiceViewModel
    {
        public int TRANMID { get; set; }
        public DateTime TRANDATE { get; set; }
        public int TRANNO { get; set; }
        public string TRANDNO { get; set; }
        public string TRANREFNO { get; set; }
        public string CATENAME { get; set; }
        public decimal TRANNAMT { get; set; }
    }
}
