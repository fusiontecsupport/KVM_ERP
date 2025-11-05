using KVM_ERP.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;

namespace KVM_ERP.Controllers
{
    [SessionExpire]
    public class PurchaseInvoiceApprovalController : Controller
    {
        private ApplicationDbContext context = new ApplicationDbContext();

        // GET: PurchaseInvoiceApproval
        [Authorize(Roles = "PurchaseInvoiceApprovalIndex")]
        public ActionResult Index()
        {
            return View();
        }

        // GET: Ajax data for DataTables - Only "Waiting for Approval" invoices
        [Authorize(Roles = "PurchaseInvoiceApprovalIndex")]
        public JsonResult GetAjaxData(JQueryDataTableParamModel param, string fromDate = null, string toDate = null)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"PurchaseInvoiceApproval GetAjaxData called - FromDate: {fromDate}, ToDate: {toDate}");
                
                // Build SQL query - Get only invoices with "Waiting for Approval" status
                // Filter by PUINSTCODE = 'PUS003' (Waiting for Approval)
                var sql = @"SELECT tm.TRANMID, tm.TRANDATE, tm.TRANNO, tm.TRANDNO, tm.TRANREFNO, tm.CATENAME, 
                           ISNULL(tm.TRANNAMT, 0) as TRANNAMT,
                           tm.DISPSTATUS,
                           ISNULL(pis.PUINSTDESC, 'N/A') as StatusDescription
                           FROM TRANSACTIONMASTER tm
                           LEFT JOIN PURCHASEINVOICESTATUS pis ON tm.DISPSTATUS = pis.PUINSTID
                           WHERE tm.REGSTRID = 2 
                           AND pis.PUINSTCODE = 'PUS003'";  // Only "Waiting for Approval"
                
                var parameters = new List<object>();
                
                // Add date filters if provided
                if (!string.IsNullOrEmpty(fromDate))
                {
                    sql += " AND tm.TRANDATE >= @p0";
                    parameters.Add(DateTime.Parse(fromDate));
                }
                
                if (!string.IsNullOrEmpty(toDate))
                {
                    sql += " AND tm.TRANDATE <= @p" + parameters.Count;
                    parameters.Add(DateTime.Parse(toDate).AddDays(1).AddSeconds(-1)); // Include full day
                }
                
                sql += " ORDER BY tm.TRANDATE DESC, tm.TRANNO DESC";
                
                // Get invoice data from TRANSACTIONMASTER
                var invoices = context.Database.SqlQuery<RawMaterialInvoiceViewModel>(sql, parameters.ToArray()).ToList();

                System.Diagnostics.Debug.WriteLine($"Found {invoices.Count} invoices waiting for approval");

                // Format data for DataTables
                var allInvoices = invoices.Select(i => new {
                    TRANMID = i.TRANMID,
                    TRANDATE = i.TRANDATE,
                    TRANNO = i.TRANNO,
                    TRANDNO = i.TRANDNO ?? "0000",
                    TRANREFNO = i.TRANREFNO ?? "-",
                    CATENAME = i.CATENAME ?? "",
                    TRANNAMT = i.TRANNAMT,
                    DISPSTATUS = i.DISPSTATUS,
                    StatusDescription = i.StatusDescription
                }).ToList();

                return Json(new { aaData = allInvoices }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in PurchaseInvoiceApproval GetAjaxData: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                return Json(new { error = "Error loading data: " + ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                context.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    // Note: RawMaterialInvoiceViewModel is defined in RawMaterialInvoiceController.cs
    // and is shared across both controllers in the same namespace
}
