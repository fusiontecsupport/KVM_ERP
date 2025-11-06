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
        [Authorize(Roles = "PurchaseInvoiceIndex")]
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
                
                // Build SQL query with date filtering - Get GRAND TOTAL from TRANSACTIONMASTER
                // TRANNAMT column stores the grand total (Subtotal + CGST + SGST + IGST)
                var sql = @"SELECT tm.TRANMID, tm.TRANDATE, tm.TRANNO, tm.TRANDNO, tm.TRANREFNO, tm.CATENAME, 
                           ISNULL(tm.TRANNAMT, 0) as TRANNAMT,
                           tm.DISPSTATUS,
                           ISNULL(pis.PUINSTDESC, 'N/A') as StatusDescription
                           FROM TRANSACTIONMASTER tm
                           LEFT JOIN PURCHASEINVOICESTATUS pis ON tm.DISPSTATUS = pis.PUINSTID
                           WHERE tm.REGSTRID = 2";
                
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

                System.Diagnostics.Debug.WriteLine($"SQL Query: {sql}");
                foreach (var invoice in invoices.Take(3))  // Log first 3 for debugging
                {
                    System.Diagnostics.Debug.WriteLine($"Invoice {invoice.TRANDNO}: TRANNAMT (Grand Total) = ₹{invoice.TRANNAMT:F2}");
                }

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
                        CFTYPE = cf.CFTYPE,
                        CFOPTN = cf.CFOPTN,
                        DORDRID = cf.DORDRID,
                        CGSTEXPRN = 0,  // Default 0, can be configured later
                        SGSTEXPRN = 0,  // Default 0, can be configured later
                        IGSTEXPRN = 0   // Default 0, can be configured later
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
                // Check if user has delete role
                if (!User.IsInRole("PurchaseInvoiceDelete"))
                {
                    return Json(new { success = false, message = "Access Denied: You do not have permission to delete records. Please contact your administrator." });
                }
                
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

                // STEP 1: Get TRANDAID values for logging (items that will become available again)
                var trandaidValues = context.Database.SqlQuery<int>(
                    @"SELECT DISTINCT TRANDAID 
                      FROM TRANSACTIONDETAIL 
                      WHERE TRANMID = @p0 AND TRANDAID > 0",
                    id
                ).ToList();

                System.Diagnostics.Debug.WriteLine($"Deleting invoice {id}. {trandaidValues.Count} items will become available: {string.Join(", ", trandaidValues)}");

                // NOTE: We do NOT update Raw Material Intake (REGSTRID=1) records
                // When invoice TRANSACTIONDETAIL is deleted, those TRANPID values automatically become available
                // because they won't appear in the NOT IN (SELECT TRANDAID...) subquery anymore

                // STEP 2: Delete tax factors
                context.Database.ExecuteSqlCommand(
                    "DELETE FROM TRANSACTIONMASTERFACTOR WHERE TRANMID = @p0",
                    id
                );

                // STEP 3: Delete invoice items (this makes TRANPID values available again)
                context.Database.ExecuteSqlCommand(
                    "DELETE FROM TRANSACTIONDETAIL WHERE TRANMID = @p0",
                    id
                );

                // STEP 4: Delete the invoice header
                context.Database.ExecuteSqlCommand(
                    "DELETE FROM TRANSACTIONMASTER WHERE TRANMID = @p0 AND REGSTRID = 2",
                    id
                );

                System.Diagnostics.Debug.WriteLine($"Invoice {id} deleted successfully. {trandaidValues.Count} items are now available for re-invoicing");
                return Json(new { success = true, message = $"Invoice deleted successfully. {trandaidValues.Count} item(s) are now available for new invoices." });
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
        [Authorize(Roles = "PurchaseInvoiceCreate,PurchaseInvoiceEdit")]
        public ActionResult Form(int? id, string source = null)
        {
            try
            {
                // Check if called from Invoice Approval page
                bool isApprovalMode = source == "approval";
                ViewBag.IsApprovalMode = isApprovalMode;
                
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

                // Get purchase invoice statuses for dropdown
                // If from Approval page: show "Active" (PUS001) and "Approved" (PUS004)
                // If from regular Invoice: show "Cancel" and "Waiting for Approval"
                if (isApprovalMode)
                {
                    ViewBag.InvoiceStatuses = context.PurchaseInvoiceStatuses
                        .Where(s => (s.DISPSTATUS == 0 || s.DISPSTATUS == null) && 
                               (s.PUINSTCODE == "PUS001" || s.PUINSTCODE == "PUS004"))  // Active and Approved
                        .OrderBy(s => s.PUINSTDESC)
                        .Select(s => new SelectListItem
                        {
                            Value = s.PUINSTID.ToString(),
                            Text = s.PUINSTDESC
                        })
                        .ToList();
                    
                    // Set default status to "Approved" for approval mode
                    var approvedStatus = context.PurchaseInvoiceStatuses
                        .FirstOrDefault(s => s.PUINSTCODE == "PUS004");
                    if (approvedStatus != null)
                    {
                        ViewBag.DefaultStatus = approvedStatus.PUINSTID;
                    }
                }
                else
                {
                    ViewBag.InvoiceStatuses = context.PurchaseInvoiceStatuses
                        .Where(s => (s.DISPSTATUS == 0 || s.DISPSTATUS == null) && 
                               (s.PUINSTCODE == "PUS002" || s.PUINSTCODE == "PUS003"))  // Cancel and Waiting for Approval
                        .OrderBy(s => s.PUINSTDESC)
                        .Select(s => new SelectListItem
                        {
                            Value = s.PUINSTID.ToString(),
                            Text = s.PUINSTDESC
                        })
                        .ToList();
                    
                    // Set default status to "Waiting for Approval" for regular mode
                    var waitingStatus = context.PurchaseInvoiceStatuses
                        .FirstOrDefault(s => s.PUINSTCODE == "PUS003");
                    if (waitingStatus != null)
                    {
                        ViewBag.DefaultStatus = waitingStatus.PUINSTID;
                    }
                }

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
                        // Check if invoice is already approved - prevent editing
                        var approvedStatus = context.PurchaseInvoiceStatuses
                            .FirstOrDefault(s => s.PUINSTCODE == "PUS004");
                        
                        bool isApproved = approvedStatus != null && invoice.DISPSTATUS == approvedStatus.PUINSTID;
                        ViewBag.IsApproved = isApproved;
                        
                        if (isApproved && !isApprovalMode)
                        {
                            // Invoice is approved and not in approval mode - prevent editing
                            TempData["ErrorMessage"] = "This invoice has been approved and cannot be edited. Please contact administrator if changes are needed.";
                            return RedirectToAction("Index");
                        }
                        
                        ViewBag.InvoiceData = invoice;
                        ViewBag.InvoiceNo = invoice.TRANNO.ToString();
                        ViewBag.InvoiceDate = invoice.TRANDATE.ToString("yyyy-MM-dd");
                        ViewBag.RefNo = invoice.TRANREFNO;
                        ViewBag.Status = invoice.DISPSTATUS;
                        ViewBag.SupplierId = invoice.TRANREFID;
                        ViewBag.IsEdit = true;
                        ViewBag.EditId = id.Value;
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
                        td.MTRLGID as MaterialGroupId,
                        ISNULL(tpc.GRADEID, 0) as GradeId,
                        g.GRADEDESC as Grade,
                        ISNULL(tpc.PCLRID, 0) as ProductionColourId,
                        pcm.PCLRDESC as ProductionColour,
                        ISNULL(tpc.RCVDTID, 0) as ReceivedTypeId,
                        rt.RCVDTDESC as ReceivedType,
                        ISNULL(tpc.FACTORYWGT, 0) as ActualWeight,
                        ISNULL(tpc.TRANPID, 0) as TRANPID
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
                        AND tpc.TRANPID IS NOT NULL
                        AND tpc.TRANPID > 0
                        AND tpc.TRANPID NOT IN (
                            SELECT DISTINCT TRANDAID 
                            FROM TRANSACTIONDETAIL invtd
                            INNER JOIN TRANSACTIONMASTER invtm ON invtd.TRANMID = invtm.TRANMID
                            INNER JOIN PURCHASEINVOICESTATUS pis ON invtm.DISPSTATUS = pis.PUINSTID
                            WHERE invtm.REGSTRID = 2 
                                AND invtd.TRANDAID > 0
                                AND pis.PUINSTCODE != 'PUS002'  -- Exclude only Cancelled invoices
                        )
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

        // Get invoice items for editing
        [HttpPost]
        public JsonResult GetInvoiceItems(int invoiceId)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"GetInvoiceItems called for invoiceId: {invoiceId}");
                
                var items = context.Database.SqlQuery<InvoiceItemEditViewModel>(@"
                    SELECT 
                        td.TRANDID,
                        td.MTRLID as ItemId,
                        m.MTRLDESC as ItemName,
                        td.MTRLGID as MaterialGroupId,
                        td.GRADEID as GradeId,
                        g.GRADEDESC as Grade,
                        td.PCLRID as ProductionColourId,
                        pcm.PCLRDESC as ProductionColour,
                        td.RCVDTID as ReceivedTypeId,
                        rt.RCVDTDESC as ReceivedType,
                        td.TRANAQTY as ActualWeight,
                        td.TRANEQTY as NetWeight,
                        td.TRANDRATE as Rate,
                        td.TRANDAMT as Amount,
                        ISNULL(td.TRANDAID, 0) as TRANPID
                    FROM TRANSACTIONDETAIL td
                    INNER JOIN MATERIALMASTER m ON td.MTRLID = m.MTRLID
                    LEFT JOIN GRADEMASTER g ON td.GRADEID = g.GRADEID
                    LEFT JOIN PRODUCTIONCOLOURMASTER pcm ON td.PCLRID = pcm.PCLRID
                    LEFT JOIN RECEIVEDTYPEMASTER rt ON td.RCVDTID = rt.RCVDTID
                    WHERE td.TRANMID = @p0
                        AND (td.DISPSTATUS = 0 OR td.DISPSTATUS IS NULL)
                    ORDER BY td.TRANDID
                ", invoiceId).ToList();

                System.Diagnostics.Debug.WriteLine($"Found {items.Count} items for invoice {invoiceId}");
                foreach (var item in items)
                {
                    System.Diagnostics.Debug.WriteLine($"  Item: {item.ItemName}, TRANPID={item.TRANPID} (checkbox will be " + (item.TRANPID > 0 ? "CHECKED" : "UNCHECKED") + ")");
                }
                
                return Json(new { success = true, data = items });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting invoice items: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Get ALL items for editing: saved items (checked) + available items (unchecked)
        [HttpPost]
        public JsonResult GetInvoiceItemsForEdit(int invoiceId)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"GetInvoiceItemsForEdit called for invoiceId: {invoiceId}");
                
                // STEP 1: Get supplier code from the invoice
                var supplierCode = context.Database.SqlQuery<string>(@"
                    SELECT CATECODE 
                    FROM TRANSACTIONMASTER 
                    WHERE TRANMID = @p0
                ", invoiceId).FirstOrDefault();
                
                if (string.IsNullOrEmpty(supplierCode))
                {
                    return Json(new { success = false, message = "Supplier not found for this invoice" });
                }
                
                System.Diagnostics.Debug.WriteLine($"Supplier code: {supplierCode}");
                
                // STEP 2: Get ALL available items from Raw Material Intake
                // Show items that are NOT invoiced OR already in THIS invoice
                var allItems = context.Database.SqlQuery<SupplierItemViewModel>(@"
                    SELECT DISTINCT
                        m.MTRLID as ItemId,
                        m.MTRLDESC as ItemName,
                        td.MTRLGID as MaterialGroupId,
                        ISNULL(tpc.GRADEID, 0) as GradeId,
                        g.GRADEDESC as Grade,
                        ISNULL(tpc.PCLRID, 0) as ProductionColourId,
                        pcm.PCLRDESC as ProductionColour,
                        ISNULL(tpc.RCVDTID, 0) as ReceivedTypeId,
                        rt.RCVDTDESC as ReceivedType,
                        ISNULL(tpc.FACTORYWGT, 0) as ActualWeight,
                        ISNULL(tpc.TRANPID, 0) as TRANPID
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
                        AND tpc.TRANPID IS NOT NULL
                        AND tpc.TRANPID > 0
                        AND (
                            tpc.TRANPID NOT IN (
                                SELECT DISTINCT TRANDAID 
                                FROM TRANSACTIONDETAIL invtd
                                INNER JOIN TRANSACTIONMASTER invtm ON invtd.TRANMID = invtm.TRANMID
                                INNER JOIN PURCHASEINVOICESTATUS pis ON invtm.DISPSTATUS = pis.PUINSTID
                                WHERE invtm.REGSTRID = 2 
                                    AND invtd.TRANDAID > 0
                                    AND pis.PUINSTCODE != 'PUS002'  -- Exclude only Cancelled invoices
                            )
                            OR tpc.TRANPID IN (
                                SELECT DISTINCT TRANDAID 
                                FROM TRANSACTIONDETAIL invtd
                                WHERE invtd.TRANMID = @p1
                                    AND invtd.TRANDAID > 0
                            )
                        )
                    ORDER BY m.MTRLDESC
                ", supplierCode, invoiceId).ToList();
                
                System.Diagnostics.Debug.WriteLine($"Found {allItems.Count} total available items");
                
                // STEP 3: Get saved items from THIS invoice
                var savedItems = context.Database.SqlQuery<InvoiceItemEditViewModel>(@"
                    SELECT 
                        td.TRANDID,
                        td.MTRLID as ItemId,
                        td.MTRLGID as MaterialGroupId,
                        td.GRADEID as GradeId,
                        td.PCLRID as ProductionColourId,
                        td.RCVDTID as ReceivedTypeId,
                        td.TRANAQTY as ActualWeight,
                        td.TRANEQTY as NetWeight,
                        td.TRANDRATE as Rate,
                        td.TRANDAMT as Amount,
                        ISNULL(td.TRANDAID, 0) as TRANPID
                    FROM TRANSACTIONDETAIL td
                    WHERE td.TRANMID = @p0
                        AND (td.DISPSTATUS = 0 OR td.DISPSTATUS IS NULL)
                ", invoiceId).ToList();
                
                System.Diagnostics.Debug.WriteLine($"Found {savedItems.Count} saved items in invoice");
                
                // STEP 4: Merge - add NetWeight, Rate, Amount to items that are saved
                var mergedItems = allItems.Select(item => {
                    // Match by TRANPID (should be unique identifier)
                    var savedItem = savedItems.FirstOrDefault(s => s.TRANPID == item.TRANPID && item.TRANPID > 0);
                    
                    var isSelected = savedItem != null;
                    
                    System.Diagnostics.Debug.WriteLine($"  Item: {item.ItemName} (TRANPID={item.TRANPID}), SavedItem={savedItem != null}, IsSelected={isSelected}");
                    
                    return new {
                        ItemId = item.ItemId,
                        ItemName = item.ItemName,
                        MaterialGroupId = item.MaterialGroupId,
                        GradeId = item.GradeId,
                        Grade = item.Grade,
                        ProductionColourId = item.ProductionColourId,
                        ProductionColour = item.ProductionColour,
                        ReceivedTypeId = item.ReceivedTypeId,
                        ReceivedType = item.ReceivedType,
                        ActualWeight = item.ActualWeight,
                        NetWeight = savedItem?.NetWeight ?? item.ActualWeight,  // Use saved or default to actual
                        Rate = savedItem?.Rate ?? 0,  // Use saved or 0
                        Amount = savedItem?.Amount ?? 0,  // Use saved or 0
                        TRANPID = item.TRANPID,
                        IsSelected = isSelected  // Checked if it was saved
                    };
                }).ToList();
                
                var selectedCount = mergedItems.Count(i => i.IsSelected);
                System.Diagnostics.Debug.WriteLine($"Merged result: {mergedItems.Count} total items, {selectedCount} selected");
                
                if (selectedCount > 0)
                {
                    System.Diagnostics.Debug.WriteLine("Selected items:");
                    foreach (var item in mergedItems.Where(i => i.IsSelected))
                    {
                        System.Diagnostics.Debug.WriteLine($"  ✓ {item.ItemName} (TRANPID={item.TRANPID})");
                    }
                }
                
                return Json(new { success = true, data = mergedItems });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in GetInvoiceItemsForEdit: {ex.Message}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Inner exception: {ex.InnerException.Message}");
                }
                return Json(new { success = false, message = ex.Message });
            }
        }

        // Get invoice tax factors for editing
        [HttpPost]
        public JsonResult GetInvoiceTaxFactors(int invoiceId)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"GetInvoiceTaxFactors called for invoiceId: {invoiceId}");
                
                var taxFactors = context.Database.SqlQuery<TaxFactorEditViewModel>(@"
                    SELECT 
                        tmf.CFID,
                        cf.CFDESC,
                        ISNULL(tmf.DEDEXPRN, 0) as CFEXPR,
                        ISNULL(CAST(tmf.DEDMODE AS INT), 0) as CFMODE,
                        ISNULL(CAST(tmf.DEDTYPE AS INT), 0) as CFTYPE,
                        ISNULL(tmf.DEDVALUE, 0) as DEDVALUE,
                        ISNULL(CAST(tmf.CFOPTN AS INT), 0) as CFOPTN,
                        ISNULL(CAST(tmf.DORDRID AS INT), 0) as DORDRID,
                        ISNULL(tmf.TRANCFCGSTEXPRN, 0) as CGSTEXPRN,
                        ISNULL(tmf.TRANCFSGSTEXPRN, 0) as SGSTEXPRN,
                        ISNULL(tmf.TRANCFIGSTEXPRN, 0) as IGSTEXPRN
                    FROM TRANSACTIONMASTERFACTOR tmf
                    LEFT JOIN COSTFACTORMASTER cf ON tmf.CFID = cf.CFID
                    WHERE tmf.TRANMID = @p0
                    ORDER BY tmf.DEDORDR
                ", invoiceId).ToList();

                System.Diagnostics.Debug.WriteLine($"Found {taxFactors.Count} tax factors for invoice {invoiceId}");
                return Json(new { success = true, data = taxFactors });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting tax factors: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"Stack trace: {ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Inner exception: {ex.InnerException.Message}");
                    System.Diagnostics.Debug.WriteLine($"Inner stack trace: {ex.InnerException.StackTrace}");
                }
                
                // Return empty data on error to prevent UI breaking
                return Json(new { success = true, data = new List<TaxFactorEditViewModel>() });
            }
        }

        // Helper method to convert number to words
        private string ConvertAmountToWords(decimal amount)
        {
            try
            {
                string[] ones = { "", "One", "Two", "Three", "Four", "Five", "Six", "Seven", "Eight", "Nine" };
                string[] teens = { "Ten", "Eleven", "Twelve", "Thirteen", "Fourteen", "Fifteen", "Sixteen", "Seventeen", "Eighteen", "Nineteen" };
                string[] tens = { "", "", "Twenty", "Thirty", "Forty", "Fifty", "Sixty", "Seventy", "Eighty", "Ninety" };

                if (amount == 0) return "Zero Rupees Only";

                int rupees = (int)amount;
                int paise = (int)((amount - rupees) * 100);

                string words = "";

                if (rupees >= 10000000) // Crores
                {
                    words += ConvertNumberToWords(rupees / 10000000, ones, teens, tens) + " Crore ";
                    rupees %= 10000000;
                }
                if (rupees >= 100000) // Lakhs
                {
                    words += ConvertNumberToWords(rupees / 100000, ones, teens, tens) + " Lakh ";
                    rupees %= 100000;
                }
                if (rupees >= 1000) // Thousands
                {
                    words += ConvertNumberToWords(rupees / 1000, ones, teens, tens) + " Thousand ";
                    rupees %= 1000;
                }
                if (rupees >= 100) // Hundreds
                {
                    words += ConvertNumberToWords(rupees / 100, ones, teens, tens) + " Hundred ";
                    rupees %= 100;
                }
                if (rupees > 0)
                {
                    words += ConvertNumberToWords(rupees, ones, teens, tens);
                }

                words = words.Trim() + " Rupees";

                if (paise > 0)
                {
                    words += " and " + ConvertNumberToWords(paise, ones, teens, tens) + " Paise";
                }

                return words + " Only";
            }
            catch
            {
                return "";
            }
        }

        private string ConvertNumberToWords(int number, string[] ones, string[] teens, string[] tens)
        {
            if (number < 10) return ones[number];
            else if (number < 20) return teens[number - 10];
            else if (number < 100) return tens[number / 10] + " " + ones[number % 10];
            return "";
        }

        // Get HSN-based GST calculation for selected items (for live display)
        [HttpPost]
        public JsonResult GetMaterialHSNGST(ItemGSTRequest request)
        {
            try
            {
                using (var context = new ApplicationDbContext())
                {
                    decimal totalCGST = 0;
                    decimal totalSGST = 0;
                    decimal totalIGST = 0;
                    decimal cgstRate = 0;
                    decimal sgstRate = 0;
                    decimal igstRate = 0;
                    bool hasGST = false;

                    if (request.items != null && request.items.Count > 0)
                    {
                        foreach (var item in request.items)
                        {
                            // Get Material Master to find HSNID
                            var material = context.MaterialMasters
                                .Where(m => m.MTRLID == item.itemId)
                                .FirstOrDefault();

                            if (material != null && material.HSNID > 0)
                            {
                                // Get HSN Code Master to find GST rates
                                var hsnCode = context.HSNCodeMasters
                                    .Where(h => h.HSNID == material.HSNID)
                                    .FirstOrDefault();

                                if (hsnCode != null)
                                {
                                    hasGST = true;

                                    // Calculate GST based on supplier state
                                    if (request.isTamilNadu)
                                    {
                                        // Tamil Nadu: CGST + SGST
                                        cgstRate = hsnCode.CGSTEXPRN;
                                        sgstRate = hsnCode.SGSTEXPRN;
                                        totalCGST += Math.Round((item.amount * cgstRate) / 100, 2);
                                        totalSGST += Math.Round((item.amount * sgstRate) / 100, 2);
                                    }
                                    else
                                    {
                                        // Other State: IGST only
                                        igstRate = hsnCode.IGSTEXPRN;
                                        totalIGST += Math.Round((item.amount * igstRate) / 100, 2);
                                    }
                                }
                            }
                        }
                    }

                    return Json(new
                    {
                        success = true,
                        gstData = new
                        {
                            totalCGST = totalCGST,
                            totalSGST = totalSGST,
                            totalIGST = totalIGST,
                            cgstRate = cgstRate,
                            sgstRate = sgstRate,
                            igstRate = igstRate,
                            hasGST = hasGST
                        }
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in GetMaterialHSNGST: {ex.Message}");
                return Json(new { success = false, message = "Error calculating GST: " + ex.Message });
            }
        }

        // Save Invoice to TRANSACTIONMASTER
        [HttpPost]
        [Authorize(Roles = "PurchaseInvoiceCreate,PurchaseInvoiceEdit")]
        public JsonResult SaveInvoice(InvoiceSaveModel model)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"========== SaveInvoice called ==========");
                System.Diagnostics.Debug.WriteLine($"InvoiceId: {model.InvoiceId}, SupplierId: {model.SupplierId}");
                System.Diagnostics.Debug.WriteLine($"InvoiceDate: {model.InvoiceDate}, RefNo: {model.RefNo}");
                System.Diagnostics.Debug.WriteLine($"Total Items in request: {model.Items?.Count ?? 0}");
                
                if (model.Items != null)
                {
                    foreach (var item in model.Items)
                    {
                        System.Diagnostics.Debug.WriteLine($"  Item: ItemId={item.ItemId}, IsSelected={item.IsSelected}, NetWeight={item.NetWeight}, Rate={item.Rate}");
                    }
                }

                // Get supplier details
                var supplier = context.SupplierMasters
                    .Where(s => s.CATEID == model.SupplierId)
                    .FirstOrDefault();

                if (supplier == null)
                {
                    return Json(new { success = false, message = "Supplier not found" });
                }

                // Get supplier state to determine GST type (CGST+SGST for Tamil Nadu, IGST for others)
                var supplierState = context.StateMasters
                    .Where(s => s.STATEID == supplier.STATEID)
                    .FirstOrDefault();

                bool isTamilNadu = supplierState != null && 
                    (supplierState.STATEDESC.ToUpper().Contains("TAMIL NADU") || 
                     supplierState.STATEDESC.ToUpper().Contains("TAMILNADU"));

                System.Diagnostics.Debug.WriteLine($"Supplier State: {supplierState?.STATEDESC}, Is Tamil Nadu: {isTamilNadu}");

                // Get COMPYID from session or default
                int compyId = Session["CompyId"] != null ? Convert.ToInt32(Session["CompyId"]) : 1;
                int regstrId = 2; // Default for Raw Material Invoice (Raw Material Intake uses 1)
                
                // Parse invoice date
                DateTime invoiceDate = DateTime.Parse(model.InvoiceDate);

                // Get current user
                string currentUser = User?.Identity?.Name ?? "System";

                int tranMId;
                int tranNo;
                string tranDNo;

                // Declare GST total variables at method scope
                decimal totalAmount = 0.00m;
                decimal totalCGST = 0.00m;
                decimal totalSGST = 0.00m;
                decimal totalIGST = 0.00m;
                string amountInWords = "";
                
                // Declare existingQuantities at method scope for approval mode
                Dictionary<int, Tuple<decimal, decimal>> existingQuantities = null;

                // Check if this is an UPDATE (edit existing invoice) or INSERT (new invoice)
                if (model.InvoiceId.HasValue && model.InvoiceId.Value > 0)
                {
                    // UPDATE existing invoice
                    tranMId = model.InvoiceId.Value;
                    
                    // Get existing TRANNO and TRANDNO - ensure it's a Raw Material Invoice (REGSTRID=2)
                    var existingData = context.Database.SqlQuery<ExistingInvoiceData>(@"
                        SELECT TRANNO, TRANDNO 
                        FROM TRANSACTIONMASTER 
                        WHERE TRANMID = @p0 AND REGSTRID = 2
                    ", tranMId).FirstOrDefault();
                    
                    if (existingData == null)
                    {
                        return Json(new { success = false, message = "Invoice not found for editing or not a Raw Material Invoice" });
                    }
                    
                    tranNo = existingData.TRANNO;
                    tranDNo = existingData.TRANDNO;

                    System.Diagnostics.Debug.WriteLine($"EDIT MODE: Updating existing invoice TRANMID={tranMId}");

                    // Update TRANSACTIONMASTER basic fields - only for Raw Material Invoice (REGSTRID=2)
                    // NOTE: GST totals will be updated after items are saved and calculated
                    var updateSql = @"
                        UPDATE TRANSACTIONMASTER SET
                            TRANDATE = @p0,
                            CATENAME = @p1,
                            CATECODE = @p2,
                            DISPSTATUS = @p3,
                            LMUSRID = @p4,
                            PRCSDATE = @p5,
                            TRANREFID = @p6,
                            TRANREFNO = @p7
                        WHERE TRANMID = @p8 AND REGSTRID = 2";

                    context.Database.ExecuteSqlCommand(updateSql,
                        invoiceDate,                    // TRANDATE
                        supplier.CATENAME,              // CATENAME (Supplier Name)
                        supplier.CATECODE,              // CATECODE (Supplier Code)
                        model.Status,                   // DISPSTATUS (0=Active, 1=Inactive)
                        currentUser,                    // LMUSRID
                        DateTime.Now,                   // PRCSDATE
                        model.SupplierId,               // TRANREFID (Supplier ID)
                        model.RefNo,                    // TRANREFNO (Reference Number)
                        tranMId                         // TRANMID (WHERE clause)
                    );

                    // If in Approval Mode, save existing TRANAQTY and TRANEQTY before deleting
                    if (model.IsApprovalMode)
                    {
                        existingQuantities = new Dictionary<int, Tuple<decimal, decimal>>();
                        var existingItems = context.Database.SqlQuery<ExistingItemQuantities>(@"
                            SELECT TRANDAID, TRANAQTY, TRANEQTY 
                            FROM TRANSACTIONDETAIL 
                            WHERE TRANMID = @p0
                        ", tranMId).ToList();
                        
                        foreach (var item in existingItems)
                        {
                            existingQuantities[item.TRANDAID] = Tuple.Create(item.TRANAQTY, item.TRANEQTY);
                        }
                        System.Diagnostics.Debug.WriteLine($"Approval Mode: Saved {existingQuantities.Count} existing quantity records");
                    }

                    // Delete existing items - only for Raw Material Invoice (REGSTRID=2)
                    context.Database.ExecuteSqlCommand(@"
                        DELETE FROM TRANSACTIONDETAIL 
                        WHERE TRANMID = @p0 
                        AND TRANMID IN (SELECT TRANMID FROM TRANSACTIONMASTER WHERE REGSTRID = 2)
                    ", tranMId);

                    System.Diagnostics.Debug.WriteLine($"Invoice updated successfully. TRANMID: {tranMId}, TRANNO: {tranNo}");
                }
                else
                {
                    // INSERT new invoice
                    // Generate TRANNO - Get next number for this COMPYID and REGSTRID
                    var maxTranNo = context.Database.SqlQuery<int?>(@"
                        SELECT MAX(TRANNO) 
                        FROM TRANSACTIONMASTER 
                        WHERE COMPYID = @p0 AND REGSTRID = @p1
                    ", compyId, regstrId).FirstOrDefault();

                    tranNo = (maxTranNo ?? 0) + 1;
                    tranDNo = tranNo.ToString("D4");

                    // Insert into TRANSACTIONMASTER - ONLY for Raw Material Invoice (REGSTRID=2)
                    var sql = @"
                        INSERT INTO TRANSACTIONMASTER (
                            TRANDATE, CATENAME, CATECODE, VECHNO, DISPSTATUS, 
                            CUSRID, LMUSRID, PRCSDATE, CLIENTWGHT, COMPYID, 
                            REGSTRID, TRANNO, TRANDNO, TRANREFID, TRANNAMT, 
                            TRANAMTWRDS, TRANREFNO,
                            TRANCGSTAMT, TRANSGSTAMT, TRANIGSTAMT,
                            TRANCGSTEXPRN, TRANSGSTEXPRN, TRANIGSTEXPRN
                        ) VALUES (
                            @p0, @p1, @p2, @p3, @p4, 
                            @p5, @p6, @p7, @p8, @p9, 
                            2, @p10, @p11, @p12, @p13, 
                            @p14, @p15,
                            @p16, @p17, @p18,
                            @p19, @p20, @p21
                        );
                        SELECT CAST(SCOPE_IDENTITY() as int)";

                    tranMId = context.Database.SqlQuery<int>(sql,
                        invoiceDate,                    // @p0 TRANDATE
                        supplier.CATENAME,              // @p1 CATENAME (Supplier Name)
                        supplier.CATECODE,              // @p2 CATECODE (Supplier Code)
                        "",                             // @p3 VECHNO (empty for invoice)
                        model.Status,                   // @p4 DISPSTATUS (0=Active, 1=Inactive)
                        currentUser,                    // @p5 CUSRID
                        currentUser,                    // @p6 LMUSRID
                        DateTime.Now,                   // @p7 PRCSDATE
                        0,                              // @p8 CLIENTWGHT (not used for invoice)
                        compyId,                        // @p9 COMPYID
                        // REGSTRID hardcoded as 2 in SQL
                        tranNo,                         // @p10 TRANNO
                        tranDNo,                        // @p11 TRANDNO
                        model.SupplierId,               // @p12 TRANREFID (Supplier ID)
                        totalAmount,                    // @p13 TRANNAMT (will be updated later)
                        amountInWords,                  // @p14 TRANAMTWRDS (will be updated later)
                        model.RefNo,                    // @p15 TRANREFNO (Reference Number)
                        totalCGST,                      // @p16 TRANCGSTAMT (will be updated later)
                        totalSGST,                      // @p17 TRANSGSTAMT (will be updated later)
                        totalIGST,                      // @p18 TRANIGSTAMT (will be updated later)
                        0.00m,                          // @p19 TRANCGSTEXPRN (will be updated later)
                        0.00m,                          // @p20 TRANSGSTEXPRN (will be updated later)
                        0.00m                           // @p21 TRANIGSTEXPRN (will be updated later)
                    ).FirstOrDefault();

                    System.Diagnostics.Debug.WriteLine($"Invoice created successfully. TRANMID: {tranMId}, TRANNO: {tranNo}");
                }

                // Save invoice items to TRANSACTIONDETAIL with GST calculations
                // FILTER: Only save items where IsSelected = true (checkbox is checked)
                if (model.Items != null && model.Items.Count > 0)
                {
                    decimal subtotal = 0.00m;
                    totalCGST = 0.00m;
                    totalSGST = 0.00m;
                    totalIGST = 0.00m;

                    // Only process SELECTED items (IsSelected = true)
                    var selectedItems = model.Items.Where(i => i.IsSelected).ToList();
                    System.Diagnostics.Debug.WriteLine($"Total items in request: {model.Items.Count}, Selected items: {selectedItems.Count}");

                    // Validate: At least one item must be selected
                    if (selectedItems.Count == 0)
                    {
                        return Json(new { success = false, message = "Please select at least one item to save in the invoice" });
                    }

                    foreach (var item in selectedItems)
                    {
                        // Get Material Master to find HSNID
                        var material = context.MaterialMasters
                            .Where(m => m.MTRLID == item.ItemId)
                            .FirstOrDefault();

                        int hsnId = 0;
                        decimal cgstRate = 0.00m;
                        decimal sgstRate = 0.00m;
                        decimal igstRate = 0.00m;
                        decimal itemCGST = 0.00m;
                        decimal itemSGST = 0.00m;
                        decimal itemIGST = 0.00m;

                        if (material != null && material.HSNID > 0)
                        {
                            hsnId = material.HSNID;

                            // Get HSN Code Master to find GST rates
                            var hsnCode = context.HSNCodeMasters
                                .Where(h => h.HSNID == material.HSNID)
                                .FirstOrDefault();

                            if (hsnCode != null)
                            {
                                // Calculate GST based on supplier state
                                if (isTamilNadu)
                                {
                                    // Tamil Nadu supplier: CGST + SGST
                                    cgstRate = hsnCode.CGSTEXPRN;
                                    sgstRate = hsnCode.SGSTEXPRN;
                                    itemCGST = Math.Round((item.Amount * cgstRate) / 100, 2);
                                    itemSGST = Math.Round((item.Amount * sgstRate) / 100, 2);
                                    System.Diagnostics.Debug.WriteLine($"  Tamil Nadu GST: CGST={cgstRate}% (₹{itemCGST}), SGST={sgstRate}% (₹{itemSGST})");
                                }
                                else
                                {
                                    // Other state supplier: IGST only
                                    igstRate = hsnCode.IGSTEXPRN;
                                    itemIGST = Math.Round((item.Amount * igstRate) / 100, 2);
                                    System.Diagnostics.Debug.WriteLine($"  Other State GST: IGST={igstRate}% (₹{itemIGST})");
                                }
                            }
                        }

                        // Calculate Net Amount (Gross Amount + GST)
                        decimal grossAmount = item.Amount; // TRANDGAMT
                        decimal netAmount = grossAmount + itemCGST + itemSGST + itemIGST; // TRANDNAMT

                        var itemSql = @"
                            INSERT INTO TRANSACTIONDETAIL (
                                TRANMID, MTRLGID, MTRLID, MTRLNBOX, MTRLCOUNTS,
                                GRADEID, PCLRID, RCVDTID, HSNID,
                                TRANAQTY, TRANDQTY, TRANEQTY, TRANDRATE, TRANDAMT,
                                TRANDDISCEXPRN, TRANDDISCAMT, TRANDGAMT,
                                TRANDCGSTEXPRN, TRANDSGSTEXPRN, TRANDIGSTEXPRN,
                                TRANDCGSTAMT, TRANDSGSTAMT, TRANDIGSTAMT, TRANDNAMT, TRANDAID,
                                CUSRID, LMUSRID, DISPSTATUS, PRCSDATE
                            ) VALUES (
                                @p0, @p1, @p2, @p3, @p4,
                                @p5, @p6, @p7, @p8,
                                @p9, @p10, @p11, @p12, @p13,
                                @p14, @p15, @p16,
                                @p17, @p18, @p19,
                                @p20, @p21, @p22, @p23, @p24,
                                @p25, @p26, @p27, @p28
                            )";

                        // TRANDAID: Store TRANPID for reference in invoice (REGSTRID=2 only)
                        // This does NOT update Raw Material Intake (REGSTRID=1) records
                        int trandaid = item.TRANPID > 0 ? item.TRANPID : 0;
                        
                        // Determine quantities based on approval mode
                        decimal tranaqty, traneqty, trandqty;
                        if (model.IsApprovalMode && existingQuantities != null && existingQuantities.ContainsKey(trandaid))
                        {
                            // Approval Mode: Keep original TRANAQTY and TRANEQTY, only update TRANDQTY
                            tranaqty = existingQuantities[trandaid].Item1;  // Original TRANAQTY
                            traneqty = existingQuantities[trandaid].Item2;  // Previous TRANEQTY
                            trandqty = item.NetWeight;                       // New value goes to TRANDQTY
                            System.Diagnostics.Debug.WriteLine($"  Approval Mode: TRANAQTY={tranaqty}, TRANEQTY={traneqty}, TRANDQTY={trandqty}");
                        }
                        else
                        {
                            // Regular Mode: NetWeight goes to both TRANEQTY and TRANDQTY
                            tranaqty = item.ActualWeight;
                            traneqty = item.NetWeight;
                            trandqty = item.NetWeight;
                        }
                        
                        System.Diagnostics.Debug.WriteLine($"  Saving item: ItemId={item.ItemId}, TRANPID={item.TRANPID}, TRANDAID={trandaid}, HSNID={hsnId}, Gross=₹{grossAmount}, CGST=₹{itemCGST}, SGST=₹{itemSGST}, IGST=₹{itemIGST}, Net=₹{netAmount}");

                        context.Database.ExecuteSqlCommand(itemSql,
                            tranMId,                 // @p0 - TRANMID
                            item.MaterialGroupId,    // @p1 - MTRLGID
                            item.ItemId,             // @p2 - MTRLID
                            0,                       // @p3 - MTRLNBOX (default 0)
                            0,                       // @p4 - MTRLCOUNTS (default 0)
                            item.GradeId,            // @p5 - GRADEID
                            item.ProductionColourId, // @p6 - PCLRID
                            item.ReceivedTypeId,     // @p7 - RCVDTID
                            hsnId,                   // @p8 - HSNID (from Material Master)
                            tranaqty,                // @p9 - TRANAQTY (Original from Raw Material Intake)
                            trandqty,                // @p10 - TRANDQTY (Approval: new value, Regular: same as TRANEQTY)
                            traneqty,                // @p11 - TRANEQTY (Approval: unchanged, Regular: NetWeight)
                            item.Rate,               // @p12 - TRANDRATE
                            item.Amount,             // @p13 - TRANDAMT
                            0.00m,                   // @p14 - TRANDDISCEXPRN (default 0.00)
                            0.00m,                   // @p15 - TRANDDISCAMT (default 0.00)
                            grossAmount,             // @p16 - TRANDGAMT (Gross Amount)
                            cgstRate,                // @p17 - TRANDCGSTEXPRN (CGST %)
                            sgstRate,                // @p18 - TRANDSGSTEXPRN (SGST %)
                            igstRate,                // @p19 - TRANDIGSTEXPRN (IGST %)
                            itemCGST,                // @p20 - TRANDCGSTAMT (CGST Amount)
                            itemSGST,                // @p21 - TRANDSGSTAMT (SGST Amount)
                            itemIGST,                // @p22 - TRANDIGSTAMT (IGST Amount)
                            netAmount,               // @p23 - TRANDNAMT (Net Amount = Gross + GST)
                            trandaid,                // @p24 - TRANDAID (Stores TRANPID reference for invoice)
                            currentUser,             // @p25 - CUSRID
                            currentUser,             // @p26 - LMUSRID
                            0,                       // @p27 - DISPSTATUS (0=Active)
                            DateTime.Now             // @p28 - PRCSDATE
                        );

                        // Add to totals
                        subtotal += item.Amount;
                        totalCGST += itemCGST;
                        totalSGST += itemSGST;
                        totalIGST += itemIGST;
                    }
                    
                    // Calculate grand total
                    totalAmount = subtotal + totalCGST + totalSGST + totalIGST;
                    amountInWords = ConvertAmountToWords(totalAmount);

                    System.Diagnostics.Debug.WriteLine($"Invoice Totals: Subtotal=₹{subtotal}, CGST=₹{totalCGST}, SGST=₹{totalSGST}, IGST=₹{totalIGST}, Grand Total=₹{totalAmount}");
                    System.Diagnostics.Debug.WriteLine($"Amount in Words: {amountInWords}");
                    System.Diagnostics.Debug.WriteLine($"Saved {selectedItems.Count} SELECTED items (out of {model.Items.Count} total items) to TRANSACTIONDETAIL");
                    
                    // IMPORTANT: TRANDAID behavior based on REGSTRID:
                    // - REGSTRID=2 (Invoice): TRANDAID stores TRANPID as reference (saved above)
                    // - REGSTRID=1 (Raw Material Intake): TRANDAID is NOT touched/updated
                    
                    // Update TRANSACTIONMASTER with calculated totals
                    var updateMasterSql = @"
                        UPDATE TRANSACTIONMASTER
                        SET TRANNAMT = @p0,
                            TRANAMTWRDS = @p1,
                            TRANCGSTAMT = @p2,
                            TRANSGSTAMT = @p3,
                            TRANIGSTAMT = @p4,
                            TRANCGSTEXPRN = @p5,
                            TRANSGSTEXPRN = @p6,
                            TRANIGSTEXPRN = @p7
                        WHERE TRANMID = @p8";

                    // Calculate average GST rates (in case multiple different rates)
                    decimal avgCGSTRate = 0.00m;
                    decimal avgSGSTRate = 0.00m;
                    decimal avgIGSTRate = 0.00m;

                    if (totalCGST > 0 && subtotal > 0)
                        avgCGSTRate = Math.Round((totalCGST / subtotal) * 100, 2);
                    if (totalSGST > 0 && subtotal > 0)
                        avgSGSTRate = Math.Round((totalSGST / subtotal) * 100, 2);
                    if (totalIGST > 0 && subtotal > 0)
                        avgIGSTRate = Math.Round((totalIGST / subtotal) * 100, 2);

                    context.Database.ExecuteSqlCommand(updateMasterSql,
                        totalAmount,      // @p0 - TRANNAMT
                        amountInWords,    // @p1 - TRANAMTWRDS
                        totalCGST,        // @p2 - TRANCGSTAMT
                        totalSGST,        // @p3 - TRANSGSTAMT
                        totalIGST,        // @p4 - TRANIGSTAMT
                        avgCGSTRate,      // @p5 - TRANCGSTEXPRN
                        avgSGSTRate,      // @p6 - TRANSGSTEXPRN
                        avgIGSTRate,      // @p7 - TRANIGSTEXPRN
                        tranMId           // @p8 - TRANMID
                    );

                    System.Diagnostics.Debug.WriteLine($"Updated TRANSACTIONMASTER: Grand Total=₹{totalAmount}, Amount in Words={amountInWords}");
                }

                // NOTE: HSN GST (CGST, SGST, IGST) is calculated and displayed on screen
                // but NOT saved to TRANSACTIONMASTERFACTOR table
                // Only manual cost factors from TAX popup are saved to TRANSACTIONMASTERFACTOR
                
                /*
                // AUTO-GENERATION OF HSN GST DISABLED - User requested only manual TAX popup factors
                // Delete existing tax factors if updating
                context.Database.ExecuteSqlCommand(@"
                    DELETE FROM TRANSACTIONMASTERFACTOR 
                    WHERE TRANMID = @p0
                ", tranMId);

                // Create GST tax factors automatically
                int taxOrder = 1;
                
                if (totalCGST > 0)
                {
                    // CGST Tax Factor
                    var cgstSql = @"
                        INSERT INTO TRANSACTIONMASTERFACTOR (
                            TRANMID, CFID, DEDEXPRN, DEDMODE, DEDTYPE, DEDORDR,
                            CFOPTN, DORDRID, DEDVALUE, TRANCFDESC, CFHSNID,
                            TRANCFCGSTEXPRN, TRANCFSGSTEXPRN, TRANCFIGSTEXPRN,
                            TRANCFCGSTAMT, TRANCFSGSTAMT, TRANCFIGSTAMT
                        ) VALUES (
                            @p0, @p1, @p2, @p3, @p4, @p5,
                            @p6, @p7, @p8, @p9, @p10,
                            @p11, @p12, @p13,
                            @p14, @p15, @p16
                        )";

                    decimal cgstAvgRate = totalCGST > 0 ? Math.Round((totalCGST / (totalAmount - totalCGST - totalSGST - totalIGST)) * 100, 2) : 0.00m;

                    context.Database.ExecuteSqlCommand(cgstSql,
                        tranMId,          // @p0 - TRANMID
                        0,                // @p1 - CFID (0 for auto-generated)
                        cgstAvgRate,      // @p2 - DEDEXPRN (CGST %)
                        0,                // @p3 - DEDMODE (0=ADD)
                        0,                // @p4 - DEDTYPE (0=%)
                        taxOrder++,       // @p5 - DEDORDR
                        0,                // @p6 - CFOPTN (0=Amount)
                        5,                // @p7 - DORDRID (5=Sales Tax)
                        totalCGST,        // @p8 - DEDVALUE
                        "CGST",           // @p9 - TRANCFDESC
                        0,                // @p10 - CFHSNID
                        cgstAvgRate,      // @p11 - TRANCFCGSTEXPRN
                        0.00m,            // @p12 - TRANCFSGSTEXPRN
                        0.00m,            // @p13 - TRANCFIGSTEXPRN
                        totalCGST,        // @p14 - TRANCFCGSTAMT
                        0.00m,            // @p15 - TRANCFSGSTAMT
                        0.00m             // @p16 - TRANCFIGSTAMT
                    );
                }

                if (totalSGST > 0)
                {
                    // SGST Tax Factor
                    var sgstSql = @"
                        INSERT INTO TRANSACTIONMASTERFACTOR (
                            TRANMID, CFID, DEDEXPRN, DEDMODE, DEDTYPE, DEDORDR,
                            CFOPTN, DORDRID, DEDVALUE, TRANCFDESC, CFHSNID,
                            TRANCFCGSTEXPRN, TRANCFSGSTEXPRN, TRANCFIGSTEXPRN,
                            TRANCFCGSTAMT, TRANCFSGSTAMT, TRANCFIGSTAMT
                        ) VALUES (
                            @p0, @p1, @p2, @p3, @p4, @p5,
                            @p6, @p7, @p8, @p9, @p10,
                            @p11, @p12, @p13,
                            @p14, @p15, @p16
                        )";

                    decimal sgstAvgRate = totalSGST > 0 ? Math.Round((totalSGST / (totalAmount - totalCGST - totalSGST - totalIGST)) * 100, 2) : 0.00m;

                    context.Database.ExecuteSqlCommand(sgstSql,
                        tranMId,          // @p0 - TRANMID
                        0,                // @p1 - CFID (0 for auto-generated)
                        sgstAvgRate,      // @p2 - DEDEXPRN (SGST %)
                        0,                // @p3 - DEDMODE (0=ADD)
                        0,                // @p4 - DEDTYPE (0=%)
                        taxOrder++,       // @p5 - DEDORDR
                        0,                // @p6 - CFOPTN (0=Amount)
                        5,                // @p7 - DORDRID (5=Sales Tax)
                        totalSGST,        // @p8 - DEDVALUE
                        "SGST",           // @p9 - TRANCFDESC
                        0,                // @p10 - CFHSNID
                        0.00m,            // @p11 - TRANCFCGSTEXPRN
                        sgstAvgRate,      // @p12 - TRANCFSGSTEXPRN
                        0.00m,            // @p13 - TRANCFIGSTEXPRN
                        0.00m,            // @p14 - TRANCFCGSTAMT
                        totalSGST,        // @p15 - TRANCFSGSTAMT
                        0.00m             // @p16 - TRANCFIGSTAMT
                    );
                }

                if (totalIGST > 0)
                {
                    // IGST Tax Factor
                    var igstSql = @"
                        INSERT INTO TRANSACTIONMASTERFACTOR (
                            TRANMID, CFID, DEDEXPRN, DEDMODE, DEDTYPE, DEDORDR,
                            CFOPTN, DORDRID, DEDVALUE, TRANCFDESC, CFHSNID,
                            TRANCFCGSTEXPRN, TRANCFSGSTEXPRN, TRANCFIGSTEXPRN,
                            TRANCFCGSTAMT, TRANCFSGSTAMT, TRANCFIGSTAMT
                        ) VALUES (
                            @p0, @p1, @p2, @p3, @p4, @p5,
                            @p6, @p7, @p8, @p9, @p10,
                            @p11, @p12, @p13,
                            @p14, @p15, @p16
                        )";

                    decimal igstAvgRate = totalIGST > 0 ? Math.Round((totalIGST / (totalAmount - totalCGST - totalSGST - totalIGST)) * 100, 2) : 0.00m;

                    context.Database.ExecuteSqlCommand(igstSql,
                        tranMId,          // @p0 - TRANMID
                        0,                // @p1 - CFID (0 for auto-generated)
                        igstAvgRate,      // @p2 - DEDEXPRN (IGST %)
                        0,                // @p3 - DEDMODE (0=ADD)
                        0,                // @p4 - DEDTYPE (0=%)
                        taxOrder++,       // @p5 - DEDORDR
                        0,                // @p6 - CFOPTN (0=Amount)
                        5,                // @p7 - DORDRID (5=Sales Tax)
                        totalIGST,        // @p8 - DEDVALUE
                        "IGST",           // @p9 - TRANCFDESC
                        0,                // @p10 - CFHSNID
                        0.00m,            // @p11 - TRANCFCGSTEXPRN
                        0.00m,            // @p12 - TRANCFSGSTEXPRN
                        igstAvgRate,      // @p13 - TRANCFIGSTEXPRN
                        0.00m,            // @p14 - TRANCFCGSTAMT
                        0.00m,            // @p15 - TRANCFSGSTAMT
                        totalIGST         // @p16 - TRANCFIGSTAMT
                    );
                }

                System.Diagnostics.Debug.WriteLine($"Auto-generated {taxOrder - 1} GST tax factors in TRANSACTIONMASTERFACTOR");
                */

                // Save user-provided MANUAL tax factors from Cost Factor TAX popup (if any)
                // NOTE: HSN GST is ONLY displayed on screen, NOT saved to database
                // ONLY manual cost factors from TAX button are saved
                if (model.TaxFactors != null && model.TaxFactors.Count > 0)
                {
                    // Delete existing tax factors before inserting new ones
                    context.Database.ExecuteSqlCommand(@"
                        DELETE FROM TRANSACTIONMASTERFACTOR 
                        WHERE TRANMID = @p0
                    ", tranMId);

                    int taxOrder = 1; // Start from 1 for manual factors

                    foreach (var tax in model.TaxFactors)
                    {
                        var manualTaxSql = @"
                            INSERT INTO TRANSACTIONMASTERFACTOR (
                                TRANMID, CFID, DEDEXPRN, DEDMODE, DEDTYPE, DEDORDR,
                                CFOPTN, DORDRID, DEDVALUE, TRANCFDESC, CFHSNID,
                                TRANCFCGSTEXPRN, TRANCFSGSTEXPRN, TRANCFIGSTEXPRN,
                                TRANCFCGSTAMT, TRANCFSGSTAMT, TRANCFIGSTAMT
                            ) VALUES (
                                @p0, @p1, @p2, @p3, @p4, @p5,
                                @p6, @p7, @p8, @p9, @p10,
                                @p11, @p12, @p13,
                                @p14, @p15, @p16
                            )";

                        context.Database.ExecuteSqlCommand(manualTaxSql,
                            tranMId,                // @p0 - TRANMID
                            tax.CFID,               // @p1 - CFID (from Cost Factor Master)
                            tax.CFEXPR,             // @p2 - DEDEXPRN (percentage like 5%)
                            tax.CFMODE,             // @p3 - DEDMODE (0=ADD, 1=DEDUCT)
                            tax.CFTYPE,             // @p4 - DEDTYPE (0=%, 1=Value)
                            taxOrder++,             // @p5 - DEDORDR (continues after HSN factors)
                            tax.CFOPTN,             // @p6 - CFOPTN
                            tax.DORDRID,            // @p7 - DORDRID
                            tax.DEDVALUE,           // @p8 - DEDVALUE (calculated amount)
                            tax.CFDESC,             // @p9 - TRANCFDESC (Cost Factor Description)
                            0,                      // @p10 - CFHSNID (0 for manual factors)
                            0.00m,                  // @p11 - TRANCFCGSTEXPRN (0 for manual)
                            0.00m,                  // @p12 - TRANCFSGSTEXPRN (0 for manual)
                            0.00m,                  // @p13 - TRANCFIGSTEXPRN (0 for manual)
                            0.00m,                  // @p14 - TRANCFCGSTAMT (0 for manual)
                            0.00m,                  // @p15 - TRANCFSGSTAMT (0 for manual)
                            0.00m                   // @p16 - TRANCFIGSTAMT (0 for manual)
                        );
                    }
                    System.Diagnostics.Debug.WriteLine($"Saved {model.TaxFactors.Count} manual tax factors from Cost Factor popup");
                }
                else
                {
                    // No manual tax factors - delete all existing tax factors
                    context.Database.ExecuteSqlCommand(@"
                        DELETE FROM TRANSACTIONMASTERFACTOR 
                        WHERE TRANMID = @p0
                    ", tranMId);
                    System.Diagnostics.Debug.WriteLine($"No manual tax factors - cleared TRANSACTIONMASTERFACTOR for TRANMID={tranMId}");
                }

                return Json(new { 
                    success = true, 
                    message = "Invoice saved successfully!",
                    tranmId = tranMId,
                    tranNo = tranNo,
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

        // Print Invoice
        [Authorize(Roles = "PurchaseInvoicePrint")]
        public ActionResult Print(int id)
        {
            try
            {
                // Get invoice header
                var invoice = context.Database.SqlQuery<InvoicePrintViewModel>(
                    @"SELECT tm.TRANMID, tm.TRANNO, tm.TRANDNO, tm.TRANREFNO, tm.TRANDATE,
                             tm.CATENAME, tm.CATECODE, tm.TRANNAMT, 
                             pis.PUINSTDESC as StatusDescription,
                             ISNULL(tm.TRANCGSTAMT, 0) as CGSTAMT,
                             ISNULL(tm.TRANSGSTAMT, 0) as SGSTAMT,
                             ISNULL(tm.TRANIGSTAMT, 0) as IGSTAMT,
                             ISNULL(tm.TRANCGSTEXPRN, 0) as CGSTPER,
                             ISNULL(tm.TRANSGSTEXPRN, 0) as SGSTPER,
                             ISNULL(tm.TRANIGSTEXPRN, 0) as IGSTPER
                      FROM TRANSACTIONMASTER tm
                      LEFT JOIN PURCHASEINVOICESTATUS pis ON tm.DISPSTATUS = pis.PUINSTID
                      WHERE tm.TRANMID = @p0 AND tm.REGSTRID = 2",
                    id
                ).FirstOrDefault();

                if (invoice == null)
                {
                    TempData["ErrorMessage"] = "Invoice not found";
                    return RedirectToAction("Index");
                }

                // Get invoice items
                invoice.Items = context.Database.SqlQuery<InvoiceItemPrintViewModel>(
                    @"SELECT td.TRANDID, m.MTRLDESC as MTRLNAME, 
                             ISNULL(g.GRADEDESC, '') as GRADEDESC,
                             ISNULL(pcm.PCLRDESC, '') as PCLRDESC,
                             ISNULL(rt.RCVDTDESC, '') as RCVDTDESC,
                             td.TRANDQTY as TRANQTY, 
                             td.TRANDRATE as TRANRATE, 
                             td.TRANDAMT
                      FROM TRANSACTIONDETAIL td
                      INNER JOIN MATERIALMASTER m ON td.MTRLID = m.MTRLID
                      LEFT JOIN GRADEMASTER g ON td.GRADEID = g.GRADEID
                      LEFT JOIN PRODUCTIONCOLOURMASTER pcm ON td.PCLRID = pcm.PCLRID
                      LEFT JOIN RECEIVEDTYPEMASTER rt ON td.RCVDTID = rt.RCVDTID
                      WHERE td.TRANMID = @p0
                      ORDER BY td.TRANDID",
                    id
                ).ToList();

                // Get tax factors
                invoice.TaxFactors = context.Database.SqlQuery<TaxFactorPrintViewModel>(
                    @"SELECT tmf.TRANMFID, 
                             ISNULL(tmf.TRANCFDESC, cf.CFDESC) as CFDESC,
                             ISNULL(CAST(tmf.CFOPTN AS INT), 0) as OPTNVALUE,
                             ISNULL(tmf.DEDEXPRN, 0) as CFRATE,
                             ISNULL(tmf.DEDVALUE, 0) as CFAMT,
                             ISNULL(CAST(tmf.DEDMODE AS INT), 0) as CFMODE
                      FROM TRANSACTIONMASTERFACTOR tmf
                      INNER JOIN COSTFACTORMASTER cf ON tmf.CFID = cf.CFID
                      WHERE tmf.TRANMID = @p0
                      ORDER BY tmf.DEDORDR",
                    id
                ).ToList();

                return View(invoice);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error loading invoice for print: {ex.Message}");
                TempData["ErrorMessage"] = "Error loading invoice: " + ex.Message;
                return RedirectToAction("Index");
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
        public string StatusDescription { get; set; }
    }

    // ViewModel for Supplier Items
    public class SupplierItemViewModel
    {
        public int ItemId { get; set; }
        public string ItemName { get; set; }
        public int MaterialGroupId { get; set; }
        public int GradeId { get; set; }
        public string Grade { get; set; }
        public int ProductionColourId { get; set; }
        public string ProductionColour { get; set; }
        public int ReceivedTypeId { get; set; }
        public string ReceivedType { get; set; }
        public decimal ActualWeight { get; set; }
        public int TRANPID { get; set; }  // Transaction Product Calculation ID
    }

    // Model for saving invoice
    public class InvoiceSaveModel
    {
        public int? InvoiceId { get; set; }  // TRANMID - null for new, value for edit
        public string InvoiceDate { get; set; }
        public string RefNo { get; set; }
        public int Status { get; set; }
        public int SupplierId { get; set; }
        public List<InvoiceItemModel> Items { get; set; }
        public List<TaxFactorModel> TaxFactors { get; set; }
        public bool IsApprovalMode { get; set; } = false; // Indicates if saving from approval page
    }

    // Model for invoice items
    public class InvoiceItemModel
    {
        public int ItemId { get; set; }          // MTRLID
        public int MaterialGroupId { get; set; }  // MTRLGID
        public int GradeId { get; set; }          // GRADEID
        public int ProductionColourId { get; set; } // PCLRID
        public int ReceivedTypeId { get; set; }   // RCVDTID
        public decimal ActualWeight { get; set; } // TRANAQTY
        public decimal NetWeight { get; set; }    // TRANDQTY
        public decimal Rate { get; set; }         // TRANDRATE
        public decimal Amount { get; set; }       // TRANDAMT
        public int TRANPID { get; set; }            // Transaction Product Calculation ID
        public bool IsSelected { get; set; }      // Whether item is selected for tax calculation
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

    // ViewModel for Invoice Item Editing
    public class InvoiceItemEditViewModel
    {
        public int TRANDID { get; set; }
        public int ItemId { get; set; }
        public string ItemName { get; set; }
        public int MaterialGroupId { get; set; }
        public int GradeId { get; set; }
        public string Grade { get; set; }
        public int ProductionColourId { get; set; }
        public string ProductionColour { get; set; }
        public int ReceivedTypeId { get; set; }
        public string ReceivedType { get; set; }
        public decimal ActualWeight { get; set; }
        public decimal NetWeight { get; set; }
        public decimal Rate { get; set; }
        public decimal Amount { get; set; }
        public int TRANPID { get; set; }  // Transaction Product Calculation ID from TRANDAID
    }

    // ViewModel for Tax Factor Editing
    public class TaxFactorEditViewModel
    {
        public int CFID { get; set; }
        public string CFDESC { get; set; }
        public decimal CFEXPR { get; set; }
        public int CFMODE { get; set; }
        public int CFTYPE { get; set; }
        public decimal DEDVALUE { get; set; }
        public int CFOPTN { get; set; }
        public int DORDRID { get; set; }
        public decimal CGSTEXPRN { get; set; }
        public decimal SGSTEXPRN { get; set; }
        public decimal IGSTEXPRN { get; set; }
    }

    // Helper class for retrieving existing invoice data
    public class ExistingInvoiceData
    {
        public int TRANNO { get; set; }
        public string TRANDNO { get; set; }
    }

    // Model for tax factors
    public class TaxFactorModel
    {
        public int CFID { get; set; }
        public string CFDESC { get; set; }
        public decimal CFEXPR { get; set; }
        public int CFMODE { get; set; }
        public int CFTYPE { get; set; }
        public decimal DEDVALUE { get; set; }
        public int CFOPTN { get; set; }
        public int DORDRID { get; set; }
        public decimal CGSTEXPRN { get; set; }
        public decimal SGSTEXPRN { get; set; }
        public decimal IGSTEXPRN { get; set; }
    }

    // Model for existing item quantities (used in approval mode)
    public class ExistingItemQuantities
    {
        public int TRANDAID { get; set; }
        public decimal TRANAQTY { get; set; }
        public decimal TRANEQTY { get; set; }
    }

    // ViewModel for Cost Factor
    public class CostFactorViewModel
    {
        public int CFID { get; set; }
        public string CFDESC { get; set; }
        public int CFMODE { get; set; }
        public int CFTYPE { get; set; }
        public decimal CFEXPR { get; set; }
        public int CFOPTN { get; set; }
        public int DORDRID { get; set; }
        public decimal CGSTEXPRN { get; set; }
        public decimal SGSTEXPRN { get; set; }
        public decimal IGSTEXPRN { get; set; }
    }

    // Model for GST calculation request
    public class ItemGSTRequest
    {
        public List<ItemGSTData> items { get; set; }
        public bool isTamilNadu { get; set; }
    }

    public class ItemGSTData
    {
        public int itemId { get; set; }
        public decimal amount { get; set; }
    }

    // ViewModel for Print Invoice
    public class InvoicePrintViewModel
    {
        public int TRANMID { get; set; }
        public int TRANNO { get; set; }
        public string TRANDNO { get; set; }
        public string TRANREFNO { get; set; }
        public DateTime TRANDATE { get; set; }
        public string CATENAME { get; set; }
        public string CATECODE { get; set; }
        public decimal TRANNAMT { get; set; }
        public string StatusDescription { get; set; }
        public decimal CGSTAMT { get; set; }
        public decimal SGSTAMT { get; set; }
        public decimal IGSTAMT { get; set; }
        public decimal CGSTPER { get; set; }
        public decimal SGSTPER { get; set; }
        public decimal IGSTPER { get; set; }
        public List<InvoiceItemPrintViewModel> Items { get; set; }
        public List<TaxFactorPrintViewModel> TaxFactors { get; set; }
    }

    public class InvoiceItemPrintViewModel
    {
        public int TRANDID { get; set; }
        public string MTRLNAME { get; set; }
        public string GRADEDESC { get; set; }
        public string PCLRDESC { get; set; }
        public string RCVDTDESC { get; set; }
        public decimal TRANQTY { get; set; }
        public decimal TRANRATE { get; set; }
        public decimal TRANDAMT { get; set; }
    }

    public class TaxFactorPrintViewModel
    {
        public int TRANMFID { get; set; }
        public string CFDESC { get; set; }
        public int OPTNVALUE { get; set; }
        public decimal CFRATE { get; set; }
        public decimal CFAMT { get; set; }
        public int CFMODE { get; set; }  // 1 = Addition, 2 = Subtraction
    }
}
