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
                      WHERE REGSTRID = 2
                      ORDER BY TRANDATE DESC, TRANNO DESC"
                ).ToList();
                
                return View(invoices);
            }
            catch (Exception ex)
            {
                return Content($"Error loading invoices: {ex.Message}");
            }
        }

        public JsonResult GetAjaxData(JQueryDataTableParamModel param, string fromDate = null, string toDate = null)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"GetAjaxData called - FromDate: {fromDate}, ToDate: {toDate}");
                
                // Build SQL query with date filtering
                var sql = @"SELECT TRANMID, TRANDATE, TRANNO, TRANDNO, TRANREFNO, CATENAME, TRANNAMT, DISPSTATUS
                           FROM TRANSACTIONMASTER
                           WHERE REGSTRID = 2";
                
                var parameters = new List<object>();
                
                // Add date filters if provided
                if (!string.IsNullOrEmpty(fromDate))
                {
                    sql += " AND TRANDATE >= @p0";
                    parameters.Add(DateTime.Parse(fromDate));
                }
                
                if (!string.IsNullOrEmpty(toDate))
                {
                    sql += " AND TRANDATE <= @p" + parameters.Count;
                    parameters.Add(DateTime.Parse(toDate).AddDays(1).AddSeconds(-1)); // Include full day
                }
                
                sql += " ORDER BY TRANDATE DESC, TRANNO DESC";
                
                // Get invoice data from TRANSACTIONMASTER
                var invoices = context.Database.SqlQuery<RawMaterialInvoiceViewModel>(sql, parameters.ToArray()).ToList();

                // Format data for DataTables
                var allInvoices = invoices.Select(i => new {
                    TRANMID = i.TRANMID,
                    TRANDATE = i.TRANDATE,
                    TRANNO = i.TRANNO,
                    TRANDNO = i.TRANDNO ?? "0000",
                    TRANREFNO = i.TRANREFNO ?? "-",
                    CATENAME = i.CATENAME ?? "",
                    TRANNAMT = i.TRANNAMT,
                    DISPSTATUS = i.DISPSTATUS
                }).ToList();

                System.Diagnostics.Debug.WriteLine($"Returning {allInvoices.Count} invoices");
                return Json(new { aaData = allInvoices }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in GetAjaxData: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                return Json(new { error = "Error loading data: " + ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        // Get Cost Factors for Tax Calculation
        [HttpPost]
        public JsonResult GetCostFactors()
        {
            try
            {
                var costFactors = context.CostFactorMasters
                    .Where(cf => (cf.DISPSTATUS == 0 || cf.DISPSTATUS == null))
                    .OrderBy(cf => cf.CFDESC)
                    .Select(cf => new
                    {
                        CFID = cf.CFID,
                        CFDESC = cf.CFDESC,
                        CFMODE = cf.CFMODE,
                        CFEXPR = cf.CFEXPR,
                        CFTYPE = cf.CFTYPE
                    })
                    .ToList();

                return Json(new { success = true, data = costFactors });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting cost factors: {ex.Message}");
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Delete Invoice
        [HttpPost]
        public JsonResult DeleteInvoice(int id)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"DeleteInvoice called for TRANMID: {id}");

                // Check if invoice exists
                var invoice = context.Database.SqlQuery<RawMaterialInvoiceViewModel>(
                    @"SELECT TRANMID, TRANDATE, TRANNO, TRANDNO, TRANREFNO, CATENAME, TRANNAMT, DISPSTATUS
                      FROM TRANSACTIONMASTER
                      WHERE TRANMID = @p0 AND REGSTRID = 2",
                    id
                ).FirstOrDefault();

                if (invoice == null)
                {
                    return Json(new { success = false, message = "Invoice not found" });
                }

                // Delete the invoice
                context.Database.ExecuteSqlCommand(
                    "DELETE FROM TRANSACTIONMASTER WHERE TRANMID = @p0 AND REGSTRID = 2",
                    id
                );

                System.Diagnostics.Debug.WriteLine($"Invoice {id} deleted successfully");
                return Json(new { success = true, message = "Invoice deleted successfully" });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error deleting invoice: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                return Json(new { success = false, message = "Error deleting invoice: " + ex.Message });
            }
        }

        // GET: Form for adding/editing invoice
        public ActionResult Form(int? id)
        {
            try
            {
                // Get suppliers for dropdown
                ViewBag.Suppliers = context.SupplierMasters
                    .Where(c => (c.DISPSTATUS == 0 || c.DISPSTATUS == null))
                    .OrderBy(c => c.CATENAME)
                    .Select(c => new SelectListItem
                    {
                        Value = c.CATEID.ToString(),
                        Text = c.CATENAME
                    })
                    .ToList();

                // If editing existing invoice, load the data
                if (id.HasValue)
                {
                    var invoice = context.Database.SqlQuery<InvoiceEditViewModel>(
                        @"SELECT tm.TRANMID, tm.TRANDATE, tm.TRANNO, tm.TRANDNO, tm.TRANREFNO, 
                                 tm.CATENAME, tm.TRANNAMT, tm.DISPSTATUS, tm.TRANREFID, tm.CATECODE
                          FROM TRANSACTIONMASTER tm
                          WHERE tm.TRANMID = @p0 AND tm.REGSTRID = 2",
                        id.Value
                    ).FirstOrDefault();

                    if (invoice != null)
                    {
                        ViewBag.InvoiceData = invoice;
                        ViewBag.InvoiceNo = invoice.TRANNO.ToString();
                        ViewBag.InvoiceDate = invoice.TRANDATE.ToString("yyyy-MM-dd");
                        ViewBag.RefNo = invoice.TRANREFNO;
                        ViewBag.Status = invoice.DISPSTATUS;
                        ViewBag.SupplierId = invoice.TRANREFID;
                    }
                }
                else
                {
                    // For new invoice, show the next TRANNO that will be generated
                    int compyId = Session["CompyId"] != null ? Convert.ToInt32(Session["CompyId"]) : 1;
                    int regstrId = 2; // Invoice register

                    var maxTranNo = context.Database.SqlQuery<int?>(@"
                        SELECT MAX(TRANNO) 
                        FROM TRANSACTIONMASTER 
                        WHERE COMPYID = @p0 AND REGSTRID = @p1
                    ", compyId, regstrId).FirstOrDefault();

                    int nextTranNo = (maxTranNo ?? 0) + 1;
                    ViewBag.InvoiceNo = nextTranNo.ToString();
                }

                return View();
            }
            catch (Exception ex)
            {
                return Content($"Error loading form: {ex.Message}");
            }
        }

        // Get supplier details (Vehicle Number from recent transactions, State, Location, Code)
        [HttpPost]
        public JsonResult GetSupplierDetails(int supplierId)
        {
            try
            {
                // Get supplier basic details
                var supplier = context.SupplierMasters
                    .Where(c => c.CATEID == supplierId)
                    .FirstOrDefault();

                if (supplier == null)
                {
                    return Json(new { success = false, message = "Supplier not found" });
                }

                // Get vehicle number from most recent transaction
                var recentVehicle = context.Database.SqlQuery<string>(@"
                    SELECT TOP 1 VECHNO 
                    FROM TRANSACTIONMASTER 
                    WHERE CATECODE = @p0 AND VECHNO IS NOT NULL AND VECHNO != ''
                    ORDER BY TRANDATE DESC
                ", supplier.CATECODE).FirstOrDefault();

                // Get state name and location name from masters
                var stateName = context.StateMasters
                    .Where(s => s.STATEID == supplier.STATEID)
                    .Select(s => s.STATEDESC)
                    .FirstOrDefault();

                var locationName = context.LocationMasters
                    .Where(l => l.LOCTID == supplier.LOCTID)
                    .Select(l => l.LOCTDESC)
                    .FirstOrDefault();

                var result = new
                {
                    VehicleNumber = recentVehicle ?? "",
                    State = stateName ?? "",
                    Location = locationName ?? "",
                    Code = supplier.CATECODE ?? ""
                };

                return Json(new { success = true, data = result });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting supplier details: {ex.Message}");
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Get items for the supplier from Raw Material Intake transactions
        [HttpPost]
        public JsonResult GetSupplierItems(int supplierId)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"GetSupplierItems called for supplierId: {supplierId}");
                
                // First get the supplier code
                var supplierCode = context.SupplierMasters
                    .Where(s => s.CATEID == supplierId)
                    .Select(s => s.CATECODE)
                    .FirstOrDefault();
                
                if (string.IsNullOrEmpty(supplierCode))
                {
                    System.Diagnostics.Debug.WriteLine($"Supplier code not found for supplierId: {supplierId}");
                    return Json(new { success = true, data = new List<SupplierItemViewModel>() });
                }
                
                System.Diagnostics.Debug.WriteLine($"Found supplier code: {supplierCode}");
                
                var items = context.Database.SqlQuery<SupplierItemViewModel>(@"
                    SELECT DISTINCT
                        m.MTRLID as ItemId,
                        m.MTRLDESC as ItemName,
                        g.GRADEDESC as Grade,
                        pcm.PCLRDESC as ProductionColour,
                        rt.RCVDTDESC as ReceivedType,
                        tpc.FACTORYWGT as ActualWeight
                    FROM TRANSACTIONMASTER tm
                    INNER JOIN TRANSACTIONDETAIL td ON tm.TRANMID = td.TRANMID
                    INNER JOIN MATERIALMASTER m ON td.MTRLID = m.MTRLID
                    LEFT JOIN TRANSACTION_PRODUCT_CALCULATION tpc ON td.TRANDID = tpc.TRANDID
                    LEFT JOIN GRADEMASTER g ON tpc.GRADEID = g.GRADEID
                    LEFT JOIN PRODUCTIONCOLOURMASTER pcm ON tpc.PCLRID = pcm.PCLRID
                    LEFT JOIN RECEIVEDTYPEMASTER rt ON tpc.RCVDTID = rt.RCVDTID
                    WHERE tm.CATECODE = @p0
                        AND tm.REGSTRID = 1
                        AND (tm.DISPSTATUS = 0 OR tm.DISPSTATUS IS NULL)
                        AND (td.DISPSTATUS = 0 OR td.DISPSTATUS IS NULL)
                    ORDER BY m.MTRLDESC
                ", supplierCode).ToList();

                System.Diagnostics.Debug.WriteLine($"Found {items.Count} items for supplier {supplierId} (code: {supplierCode})");
                return Json(new { success = true, data = items });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting supplier items: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Save Invoice to TRANSACTIONMASTER
        [HttpPost]
        public JsonResult SaveInvoice(InvoiceSaveModel model)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"SaveInvoice called for supplier: {model.SupplierId}");

                // Get supplier details
                var supplier = context.SupplierMasters
                    .Where(s => s.CATEID == model.SupplierId)
                    .FirstOrDefault();

                if (supplier == null)
                {
                    return Json(new { success = false, message = "Supplier not found" });
                }

                // Get COMPYID from session or default
                int compyId = Session["CompyId"] != null ? Convert.ToInt32(Session["CompyId"]) : 1;
                int regstrId = 2; // Default for Raw Material Invoice (Raw Material Intake uses 1)

                // Generate TRANNO - Get next number for this COMPYID and REGSTRID
                var maxTranNo = context.Database.SqlQuery<int?>(@"
                    SELECT MAX(TRANNO) 
                    FROM TRANSACTIONMASTER 
                    WHERE COMPYID = @p0 AND REGSTRID = @p1
                ", compyId, regstrId).FirstOrDefault();

                int newTranNo = (maxTranNo ?? 0) + 1;

                // Generate TRANDNO based on TRANNO (format: 0001, 0002, etc.)
                string tranDNo = newTranNo.ToString("D4");

                // Set total amount to 0.00 (default value)
                decimal totalAmount = 0.00m;

                // Parse invoice date
                DateTime invoiceDate = DateTime.Parse(model.InvoiceDate);

                // Get current user
                string currentUser = User?.Identity?.Name ?? "System";

                // Insert into TRANSACTIONMASTER
                var sql = @"
                    INSERT INTO TRANSACTIONMASTER (
                        TRANDATE, CATENAME, CATECODE, VECHNO, DISPSTATUS, 
                        CUSRID, LMUSRID, PRCSDATE, CLIENTWGHT, COMPYID, 
                        REGSTRID, TRANNO, TRANDNO, TRANREFID, TRANNAMT, 
                        TRANAMTWRDS, TRANREFNO
                    ) VALUES (
                        @p0, @p1, @p2, @p3, @p4, 
                        @p5, @p6, @p7, @p8, @p9, 
                        @p10, @p11, @p12, @p13, @p14, 
                        @p15, @p16
                    );
                    SELECT CAST(SCOPE_IDENTITY() as int)";

                var newTranMId = context.Database.SqlQuery<int>(sql,
                    invoiceDate,                    // TRANDATE
                    supplier.CATENAME,              // CATENAME (Supplier Name)
                    supplier.CATECODE,              // CATECODE (Supplier Code)
                    "",                             // VECHNO (empty for invoice)
                    model.Status,                   // DISPSTATUS (0=Active, 1=Inactive)
                    currentUser,                    // CUSRID
                    currentUser,                    // LMUSRID
                    DateTime.Now,                   // PRCSDATE
                    0,                              // CLIENTWGHT (not used for invoice)
                    compyId,                        // COMPYID
                    regstrId,                       // REGSTRID (2 for invoice)
                    newTranNo,                      // TRANNO
                    tranDNo,                        // TRANDNO
                    model.SupplierId,               // TRANREFID (Supplier ID)
                    totalAmount,                    // TRANNAMT
                    null,                           // TRANAMTWRDS (amount in words - can be added later)
                    model.RefNo                     // TRANREFNO (Reference Number)
                ).FirstOrDefault();

                System.Diagnostics.Debug.WriteLine($"Invoice saved successfully. TRANMID: {newTranMId}, TRANNO: {newTranNo}");

                return Json(new { 
                    success = true, 
                    message = "Invoice saved successfully!",
                    tranmId = newTranMId,
                    tranNo = newTranNo,
                    tranDNo = tranDNo
                });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error saving invoice: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                return Json(new { success = false, message = "Error saving invoice: " + ex.Message });
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
        public short DISPSTATUS { get; set; }
    }

    // ViewModel for Supplier Items
    public class SupplierItemViewModel
    {
        public int ItemId { get; set; }
        public string ItemName { get; set; }
        public string Grade { get; set; }
        public string ProductionColour { get; set; }
        public string ReceivedType { get; set; }
        public decimal? ActualWeight { get; set; }
    }

    // Model for saving invoice
    public class InvoiceSaveModel
    {
        public string InvoiceDate { get; set; }
        public string RefNo { get; set; }
        public int Status { get; set; }
        public int SupplierId { get; set; }
        public List<InvoiceItemModel> Items { get; set; }
    }

    // Model for invoice items
    public class InvoiceItemModel
    {
        public int ItemId { get; set; }
        public decimal NetWeight { get; set; }
        public decimal Rate { get; set; }
        public decimal Amount { get; set; }
    }

    // Model for editing invoice
    public class InvoiceEditViewModel
    {
        public int TRANMID { get; set; }
        public DateTime TRANDATE { get; set; }
        public int TRANNO { get; set; }
        public string TRANDNO { get; set; }
        public string TRANREFNO { get; set; }
        public string CATENAME { get; set; }
        public decimal TRANNAMT { get; set; }
        public short DISPSTATUS { get; set; }
        public int TRANREFID { get; set; }
        public string CATECODE { get; set; }
    }
}
