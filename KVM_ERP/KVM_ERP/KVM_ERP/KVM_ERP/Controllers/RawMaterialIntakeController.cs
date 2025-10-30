using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using KVM_ERP.Models;
using Newtonsoft.Json;

namespace KVM_ERP.Controllers
{
    public class RawMaterialIntakeController : Controller
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: RawMaterialIntake
        public ActionResult Index()
        {
            return View();
        }

        // GET: RawMaterialIntake/Form
        public ActionResult Form(int? id)
        {
            var model = new TransactionMaster();

            // Populate supplier dropdown (enabled suppliers only)
            var suppliers = db.SupplierMasters
                .Where(s => s.DISPSTATUS == 0)
                .OrderBy(s => s.CATENAME)
                .Select(s => new { s.CATEID, s.CATENAME, s.CATECODE, s.DISPSTATUS })
                .ToList();

            // Populate packing masters dropdown for modal
            var packingMasters = db.PackingMasters
                .Where(p => p.DISPSTATUS == 0)
                .OrderBy(p => p.PACKMDESC)
                .Select(p => new SelectListItem { Text = p.PACKMDESC, Value = p.PACKMID.ToString() })
                .ToList();
            ViewBag.PackingMasters = packingMasters;

            // Populate Grade dropdown (enabled only)
            var grades = db.GradeMasters
                .Where(g => g.DISPSTATUS == 0)
                .OrderBy(g => g.GRADEDESC)
                .Select(g => new SelectListItem { Text = g.GRADEDESC, Value = g.GRADEID.ToString() })
                .ToList();
            grades.Insert(0, new SelectListItem { Text = "-- Select Grade --", Value = "" });
            ViewBag.Grades = grades;

            // Populate Production Colour dropdown (enabled only)
            var colours = db.ProductionColourMasters
                .Where(c => c.DISPSTATUS == 0)
                .OrderBy(c => c.PCLRDESC)
                .Select(c => new SelectListItem { Text = c.PCLRDESC, Value = c.PCLRID.ToString() })
                .ToList();
            colours.Insert(0, new SelectListItem { Text = "-- Select Colour --", Value = "" });
            ViewBag.ProductionColours = colours;

            // Populate Received Type dropdown (enabled only)
            var receivedTypes = db.ReceivedTypeMasters
                .Where(r => r.DISPSTATUS == 0)
                .OrderBy(r => r.RCVDTDESC)
                .Select(r => new SelectListItem { Text = r.RCVDTDESC, Value = r.RCVDTID.ToString() })
                .ToList();
            receivedTypes.Insert(0, new SelectListItem { Text = "-- Select Type --", Value = "" });
            ViewBag.ReceivedTypes = receivedTypes;

            // We'll build this list after we know if we're editing to set Selected
            List<SelectListItem> supplierListItems;

            // Status list (selected set below based on model)
            Func<short, SelectList> buildStatus = (short selected) => new SelectList(new[]
            {
                new SelectListItem { Text = "Enabled", Value = "0" },
                new SelectListItem { Text = "Disabled", Value = "1" }
            }, "Value", "Text", selected.ToString());

            // Material Groups for details table
            var mgroups = db.MaterialGroupMasters
                .Where(g => g.DISPSTATUS == 0)
                .OrderBy(g => g.MTRLGDESC)
                .Select(g => new SelectListItem { Text = g.MTRLGDESC, Value = g.MTRLGID.ToString() })
                .ToList();
            ViewBag.MaterialGroups = mgroups;

            if (id != null && id > 0)
            {
                // Edit
                model = db.TransactionMasters.FirstOrDefault(t => t.TRANMID == id) ?? new TransactionMaster();
                // Preselect supplier by code (preferred) or name
                var sel = suppliers.FirstOrDefault(x => x.CATECODE == model.CATECODE)
                          ?? suppliers.FirstOrDefault(x => x.CATENAME == model.CATENAME);
                string selectedSupplierId = sel != null ? sel.CATEID.ToString() : "";

                // If not found among enabled suppliers, include the disabled one so edit still shows selection
                if (string.IsNullOrEmpty(selectedSupplierId))
                {
                    var disabledSupplier = db.SupplierMasters
                        .Where(x => x.CATECODE == model.CATECODE || x.CATENAME == model.CATENAME)
                        .OrderBy(x => x.CATENAME)
                        .Select(x => new { x.CATEID, x.CATENAME, x.CATECODE, x.DISPSTATUS })
                        .FirstOrDefault();
                    if (disabledSupplier != null)
                    {
                        // append to list with (Disabled) tag
                        suppliers.Add(new { disabledSupplier.CATEID, CATENAME = disabledSupplier.CATENAME + " (Disabled)", disabledSupplier.CATECODE, disabledSupplier.DISPSTATUS });
                        selectedSupplierId = disabledSupplier.CATEID.ToString();
                    }
                }

                supplierListItems = suppliers
                    .Select(s => new SelectListItem
                    {
                        Text = s.CATENAME,
                        Value = s.CATEID.ToString(),
                        Selected = selectedSupplierId == s.CATEID.ToString()
                    })
                    .ToList();
                ViewBag.SupplierList = supplierListItems;
                ViewBag.DISPSTATUS = buildStatus(model.DISPSTATUS);

                // Load existing details for edit
                var details = db.Database.SqlQuery<DetailRow>(
                    "SELECT TRANDID, TRANMID, MTRLGID, MTRLID, MTRLNBOX, MTRLCOUNTS FROM TRANSACTIONDETAIL WHERE TRANMID = @p0 ORDER BY TRANDID",
                    model.TRANMID).ToList();
                ViewBag.DetailsJson = JsonConvert.SerializeObject(details);

                // Load existing quality check for edit
                var qualityCheck = db.TransactionQualityChecks.FirstOrDefault(q => q.TRANMID == model.TRANMID);
                ViewBag.QualityCheckJson = qualityCheck != null ? JsonConvert.SerializeObject(qualityCheck) : "null";
            }
            else
            {
                // Add: pre-fill defaults
                try
                {
                    var nextNo = db.Database.SqlQuery<int>("SELECT ISNULL(MAX(TRANMID),0)+1 FROM TRANSACTIONMASTER").FirstOrDefault();
                    model.TRANMID = nextNo;
                }
                catch { model.TRANMID = 1; }
                model.TRANDATE = DateTime.Today;
                model.DISPSTATUS = 0; // Enabled by default

                supplierListItems = suppliers
                    .Select(s => new SelectListItem
                    {
                        Text = s.CATENAME,
                        Value = s.CATEID.ToString()
                    }).ToList();
                ViewBag.SupplierList = supplierListItems;
                ViewBag.DISPSTATUS = buildStatus(model.DISPSTATUS);
            }

            // For client-side auto-fill of code from supplier, pass minimal map
            ViewBag.SupplierCodeMap = suppliers.ToDictionary(s => s.CATEID.ToString(), s => s.CATECODE ?? "");

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult savedata(TransactionMaster tab, int? SupplierId, string detailRowsJson, string qualityCheckJson)
        {
            try
            {
                var details = new List<DetailRow>();
                if (!string.IsNullOrWhiteSpace(detailRowsJson))
                {
                    details = JsonConvert.DeserializeObject<List<DetailRow>>(detailRowsJson) ?? new List<DetailRow>();
                }

                // Parse quality check data
                TransactionQualityCheck qualityCheck = null;
                if (!string.IsNullOrWhiteSpace(qualityCheckJson))
                {
                    qualityCheck = JsonConvert.DeserializeObject<TransactionQualityCheck>(qualityCheckJson);
                }

                if (SupplierId.HasValue && SupplierId.Value > 0)
                {
                    var sup = db.SupplierMasters.FirstOrDefault(x => x.CATEID == SupplierId.Value);
                    if (sup != null)
                    {
                        tab.CATENAME = sup.CATENAME;
                        tab.CATECODE = sup.CATECODE;
                    }
                }

                if (tab.TRANMID > 0 && db.TransactionMasters.Any(x => x.TRANMID == tab.TRANMID))
                {
                    // Update
                    var existing = db.TransactionMasters.FirstOrDefault(x => x.TRANMID == tab.TRANMID);
                    if (existing != null)
                    {
                        existing.TRANDATE = tab.TRANDATE;
                        existing.CATENAME = tab.CATENAME;
                        existing.CATECODE = tab.CATECODE;
                        existing.VECHNO = tab.VECHNO;
                        existing.CLIENTWGHT = tab.CLIENTWGHT;
                        existing.DISPSTATUS = tab.DISPSTATUS;
                        existing.LMUSRID = User?.Identity?.Name ?? existing.LMUSRID;
                        existing.PRCSDATE = DateTime.Now; // treat as last modified for simplicity
                        
                        // Update TRANREFID if supplier changed
                        if (SupplierId.HasValue && SupplierId.Value > 0)
                        {
                            existing.TRANREFID = SupplierId.Value;
                        }
                        
                        db.SaveChanges();

                        // Load existing details for this master
                        var existingDetails = db.Database.SqlQuery<DetailRow>(
                            "SELECT TRANDID, TRANMID, MTRLGID, MTRLID, MTRLNBOX, MTRLCOUNTS FROM TRANSACTIONDETAIL WHERE TRANMID = @p0",
                            existing.TRANMID).ToList();

                        var postedIds = new HashSet<int>(details.Where(x => x.TRANDID > 0).Select(x => x.TRANDID));
                        var toDelete = existingDetails.Where(x => !postedIds.Contains(x.TRANDID)).Select(x => x.TRANDID).ToList();

                        // Delete removed rows
                        foreach (var delId in toDelete)
                        {
                            db.Database.ExecuteSqlCommand("DELETE FROM TRANSACTIONDETAIL WHERE TRANDID = @p0", delId);
                        }

                        // Upsert rows
                        foreach (var d in details)
                        {
                            if (d.MTRLGID > 0 && d.MTRLID > 0 && d.MTRLNBOX > 0 && d.MTRLCOUNTS > 0)
                            {
                                if (d.TRANDID > 0 && existingDetails.Any(ed => ed.TRANDID == d.TRANDID))
                                {
                                    // UPDATE: preserve CUSRID, only change values and LMUSRID/PRCSDATE
                                    db.Database.ExecuteSqlCommand(@"
                                        UPDATE TRANSACTIONDETAIL
                                        SET MTRLGID = @p1, MTRLID = @p2, MTRLNBOX = @p3, MTRLCOUNTS = @p4,
                                            LMUSRID = @p5, PRCSDATE = @p6
                                        WHERE TRANDID = @p0",
                                        d.TRANDID, d.MTRLGID, d.MTRLID, d.MTRLNBOX, d.MTRLCOUNTS,
                                        User?.Identity?.Name ?? "System", DateTime.Now);
                                }
                                else
                                {
                                    // INSERT during edit: preserve creator by using master CUSRID; set LMUSRID to current user
                                    db.Database.ExecuteSqlCommand(@"
                                        INSERT INTO TRANSACTIONDETAIL (TRANMID, MTRLGID, MTRLID, MTRLNBOX, MTRLCOUNTS, CUSRID, LMUSRID, DISPSTATUS, PRCSDATE)
                                        VALUES (@p0, @p1, @p2, @p3, @p4, @p5, @p6, 0, @p7)",
                                        existing.TRANMID, d.MTRLGID, d.MTRLID, d.MTRLNBOX, d.MTRLCOUNTS,
                                        existing.CUSRID, User?.Identity?.Name ?? "System", DateTime.Now);
                                }
                            }
                        }

                        // Handle Quality Check (same pattern as details)
                        if (qualityCheck != null && qualityCheck.LABOID > 0)
                        {
                            var existingQualityCheck = db.Database.SqlQuery<int>(
                                "SELECT COUNT(*) FROM TRANSACTION_QUALITY_CHECK WHERE TRANMID = @p0", existing.TRANMID).FirstOrDefault();

                            if (existingQualityCheck > 0)
                            {
                                // UPDATE: preserve CUSRID, only change values and LMUSRID/PRCSDATE
                                db.Database.ExecuteSqlCommand(@"
                                    UPDATE TRANSACTION_QUALITY_CHECK
                                    SET LABOID = @p1, STATUS = @p2, REMARKS = @p3, DONEBY = @p4, VERIFIEDBY = @p5,
                                        LOTDATE = @p6, LMUSRID = @p7, PRCSDATE = @p8
                                    WHERE TRANMID = @p0",
                                    existing.TRANMID, qualityCheck.LABOID, qualityCheck.STATUS, qualityCheck.REMARKS?.Trim(),
                                    qualityCheck.DONEBY?.Trim(), qualityCheck.VERIFIEDBY?.Trim(), qualityCheck.LOTDATE,
                                    User?.Identity?.Name ?? "System", DateTime.Now);
                            }
                            else
                            {
                                // INSERT during edit: preserve creator by using master CUSRID; set LMUSRID to current user
                                db.Database.ExecuteSqlCommand(@"
                                    INSERT INTO TRANSACTION_QUALITY_CHECK (TRANMID, LABOID, STATUS, REMARKS, DONEBY, VERIFIEDBY, LOTDATE, CUSRID, LMUSRID, DISPSTATUS, PRCSDATE)
                                    VALUES (@p0, @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, 0, @p9)",
                                    existing.TRANMID, qualityCheck.LABOID, qualityCheck.STATUS, qualityCheck.REMARKS?.Trim(),
                                    qualityCheck.DONEBY?.Trim(), qualityCheck.VERIFIEDBY?.Trim(), qualityCheck.LOTDATE,
                                    existing.CUSRID, User?.Identity?.Name ?? "System", DateTime.Now);
                            }
                        }

                        TempData["SuccessMessage"] = "Updated successfully";
                        return RedirectToAction("Index");
                    }
                }

                // Insert
                tab.CUSRID = User?.Identity?.Name ?? "System";
                tab.LMUSRID = tab.CUSRID;
                tab.PRCSDATE = DateTime.Now;
                
                // Get COMPYID from session
                int compyId = Session["compyid"] != null ? Convert.ToInt32(Session["compyid"]) : 1;
                
                // Get next TRANNO (auto-increment)
                var maxTranNo = db.Database.SqlQuery<int?>("SELECT MAX(TRANNO) FROM TRANSACTIONMASTER WHERE COMPYID = @p0", compyId).FirstOrDefault();
                int nextTranNo = (maxTranNo ?? 0) + 1;
                
                // Generate TRANDNO as 000 + TRANNO
                string tranDNo = "000" + nextTranNo.ToString();
                
                // Get supplier ID for TRANREFID
                int tranRefId = SupplierId.HasValue && SupplierId.Value > 0 ? SupplierId.Value : 0;
                
                // Set new field values
                tab.COMPYID = compyId;
                tab.REGSTRID = 1; // Default value
                tab.TRANNO = nextTranNo;
                tab.TRANDNO = tranDNo;
                tab.TRANREFID = tranRefId;
                tab.TRANNAMT = 0.00m; // Default 0.00
                tab.TRANAMTWRDS = "Nil"; // Default "Nil"
                tab.TRANREFNO = "-"; // Default "-"

                // Insert master and get new TRANMID
                var newId = db.Database.SqlQuery<int>(@"
                    INSERT INTO TRANSACTIONMASTER (TRANDATE, CATENAME, CATECODE, VECHNO, CLIENTWGHT, DISPSTATUS, CUSRID, LMUSRID, PRCSDATE,
                                                   COMPYID, REGSTRID, TRANNO, TRANDNO, TRANREFID, TRANNAMT, TRANAMTWRDS, TRANREFNO)
                    VALUES (@p0, @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10, @p11, @p12, @p13, @p14, @p15, @p16); 
                    SELECT CAST(SCOPE_IDENTITY() AS INT);
                ", tab.TRANDATE, tab.CATENAME ?? "", tab.CATECODE ?? "", tab.VECHNO ?? "",
                   tab.CLIENTWGHT, tab.DISPSTATUS, tab.CUSRID, tab.LMUSRID, tab.PRCSDATE,
                   tab.COMPYID, tab.REGSTRID, tab.TRANNO, tab.TRANDNO, tab.TRANREFID, tab.TRANNAMT, tab.TRANAMTWRDS, tab.TRANREFNO).FirstOrDefault();

                // Insert details
                foreach (var d in details)
                {
                    if (d.MTRLGID > 0 && d.MTRLID > 0 && d.MTRLNBOX > 0 && d.MTRLCOUNTS > 0)
                    {
                        db.Database.ExecuteSqlCommand(@"
                            INSERT INTO TRANSACTIONDETAIL (TRANMID, MTRLGID, MTRLID, MTRLNBOX, MTRLCOUNTS, CUSRID, LMUSRID, DISPSTATUS, PRCSDATE)
                            VALUES (@p0, @p1, @p2, @p3, @p4, @p5, @p6, 0, @p7)",
                            newId, d.MTRLGID, d.MTRLID, d.MTRLNBOX, d.MTRLCOUNTS,
                            User?.Identity?.Name ?? "System", User?.Identity?.Name ?? "System", DateTime.Now);
                    }
                }

                // Insert quality check (same pattern as details)
                if (qualityCheck != null && qualityCheck.LABOID > 0)
                {
                    db.Database.ExecuteSqlCommand(@"
                        INSERT INTO TRANSACTION_QUALITY_CHECK (TRANMID, LABOID, STATUS, REMARKS, DONEBY, VERIFIEDBY, LOTDATE, CUSRID, LMUSRID, DISPSTATUS, PRCSDATE)
                        VALUES (@p0, @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, 0, @p9)",
                        newId, qualityCheck.LABOID, qualityCheck.STATUS, qualityCheck.REMARKS?.Trim(),
                        qualityCheck.DONEBY?.Trim(), qualityCheck.VERIFIEDBY?.Trim(), qualityCheck.LOTDATE,
                        User?.Identity?.Name ?? "System", User?.Identity?.Name ?? "System", DateTime.Now);
                }

                TempData["SuccessMessage"] = "Added successfully";
                return RedirectToAction("Index");
            }
            catch (Exception ex)
            {
                ViewBag.msg = $"<div class='alert alert-danger'>Error: {ex.Message}</div>";
            }

            // Repopulate dropdowns on error
            var suppliers = db.SupplierMasters
                .Where(s => s.DISPSTATUS == 0)
                .OrderBy(s => s.CATENAME)
                .Select(s => new { s.CATEID, s.CATENAME, s.CATECODE })
                .ToList();
            ViewBag.SupplierList = suppliers
                .Select(s => new SelectListItem { Text = s.CATENAME, Value = s.CATEID.ToString() })
                .ToList();
            ViewBag.DISPSTATUS = new SelectList(new[]
            {
                new SelectListItem { Text = "Enabled", Value = "0" },
                new SelectListItem { Text = "Disabled", Value = "1" }
            }, "Value", "Text", tab.DISPSTATUS.ToString());
            ViewBag.SupplierCodeMap = suppliers.ToDictionary(s => s.CATEID.ToString(), s => s.CATECODE ?? "");

            return View("Form", tab);
        }

        // JSON: Products by Material Group (enabled only)
        public JsonResult GetProducts(int groupId)
        {
            var prods = db.MaterialMasters
                .Where(m => m.MTRLGID == groupId && m.DISPSTATUS == 0)
                .OrderBy(m => m.MTRLDESC)
                .Select(m => new { id = m.MTRLID, text = m.MTRLDESC })
                .ToList();
            return Json(prods, JsonRequestBehavior.AllowGet);
        }

        // AJAX: RawMaterialIntake/GetAjaxData
        public ActionResult GetAjaxData(string fromDate = null, string toDate = null)
        {
            try
            {
                // Debug logging
                System.Diagnostics.Debug.WriteLine($"[GetAjaxData] fromDate: {fromDate}, toDate: {toDate}");
                // Build dynamic WHERE clause for date filtering
                string whereClause = "";
                var parameters = new List<object>();
                int paramIndex = 0;

                if (!string.IsNullOrEmpty(fromDate))
                {
                    DateTime fromDateTime;
                    if (DateTime.TryParse(fromDate, out fromDateTime))
                    {
                        whereClause += $" AND tm.TRANDATE >= @p{paramIndex}";
                        parameters.Add(fromDateTime.Date);
                        paramIndex++;
                    }
                }

                if (!string.IsNullOrEmpty(toDate))
                {
                    DateTime toDateTime;
                    if (DateTime.TryParse(toDate, out toDateTime))
                    {
                        whereClause += $" AND tm.TRANDATE <= @p{paramIndex}";
                        parameters.Add(toDateTime.Date.AddDays(1).AddSeconds(-1)); // Include full day
                        paramIndex++;
                    }
                }

                // Build the SQL query with optional date filtering
                string sql = $@"SELECT tm.TRANMID, tm.TRANDATE, tm.CATENAME, tm.CATECODE, tm.VECHNO, tm.DISPSTATUS,
                             ISNULL(p.PRODUCTS,'') AS PRODUCTS
                      FROM TRANSACTIONMASTER tm
                      LEFT JOIN (
                         SELECT td.TRANMID,
                                STUFF((
                                   SELECT ', ' + m.MTRLDESC
                                   FROM TRANSACTIONDETAIL td2
                                   INNER JOIN MATERIALMASTER m ON m.MTRLID = td2.MTRLID
                                   WHERE td2.TRANMID = td.TRANMID
                                   FOR XML PATH(''), TYPE).value('.','NVARCHAR(MAX)'),1,2,'') AS PRODUCTS
                         FROM TRANSACTIONDETAIL td
                         GROUP BY td.TRANMID
                      ) p ON p.TRANMID = tm.TRANMID
                      WHERE 1=1 {whereClause}
                      ORDER BY tm.TRANDATE DESC, tm.TRANMID DESC";

                // Debug logging
                System.Diagnostics.Debug.WriteLine($"[GetAjaxData] SQL: {sql}");
                System.Diagnostics.Debug.WriteLine($"[GetAjaxData] Parameters: {string.Join(", ", parameters)}");

                // Execute query with parameters
                var rows = parameters.Count > 0 
                    ? db.Database.SqlQuery<TransactionRow>(sql, parameters.ToArray()).ToList()
                    : db.Database.SqlQuery<TransactionRow>(sql).ToList();

                System.Diagnostics.Debug.WriteLine($"[GetAjaxData] Returned {rows.Count} rows");

                var data = rows.Select((r, idx) => new
                {
                    TRANMID = r.TRANMID,
                    TRANDATE = r.TRANDATE.ToString("yyyy-MM-dd"), // ISO for stable ordering; format on client if needed
                    CATENAME = r.CATENAME ?? string.Empty,
                    CATECODE = r.CATECODE ?? string.Empty,
                    VECHNO = r.VECHNO ?? string.Empty,
                    Products = r.PRODUCTS ?? string.Empty,
                    DISPSTATUS = r.DISPSTATUS == 0 ? "Enabled" : "Disabled",
                    StatusBadge = r.DISPSTATUS == 0
                        ? "<span class='badge badge-success'>Enabled</span>"
                        : "<span class='badge badge-danger'>Disabled</span>"
                }).ToList();

                return Json(new { data = data }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { error = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        // Delete method for AJAX calls (match masters pattern)
        [HttpPost]
        public ActionResult Del(int id)
        {
            try
            {
                var exists = db.Database.SqlQuery<int>("SELECT COUNT(1) FROM TRANSACTIONMASTER WHERE TRANMID = @p0", id).FirstOrDefault();
                if (exists == 0)
                {
                    return Json("Record not found");
                }
                db.Database.ExecuteSqlCommand("DELETE FROM TRANSACTIONMASTER WHERE TRANMID = @p0", id);
                return Json("Successfully deleted");
            }
            catch (Exception ex)
            {
                return Json("Error: " + ex.Message);
            }
        }

        private class TransactionRow
        {
            public int TRANMID { get; set; }
            public DateTime TRANDATE { get; set; }
            public string CATENAME { get; set; }
            public string CATECODE { get; set; }
            public string VECHNO { get; set; }
            public short DISPSTATUS { get; set; }
            public string PRODUCTS { get; set; }
        }

        private class DetailRow
        {
            public int TRANDID { get; set; }
            public int TRANMID { get; set; }
            public int MTRLGID { get; set; }
            public int MTRLID { get; set; }
            public int MTRLNBOX { get; set; }
            public int MTRLCOUNTS { get; set; }
        }

        // Get packing type fields based on packing master
        public JsonResult GetPackingTypeFields(int packingId)
        {
            try
            {
                var packingMaster = db.PackingMasters.FirstOrDefault(p => p.PACKMID == packingId);
                if (packingMaster == null)
                {
                    return Json(new { success = false, message = "Packing master not found" }, JsonRequestBehavior.AllowGet);
                }

                // Get actual packing type masters mapped to this packing master
                var packingTypes = db.PackingTypeMasters
                    .Where(pt => pt.PACKMID == packingId && pt.DISPSTATUS == 0)
                    .OrderBy(pt => pt.PACKTMCODE)
                    .Select(pt => new { 
                        label = pt.PACKTMDESC, 
                        code = pt.PACKTMCODE,
                        id = pt.PACKTMID
                    })
                    .ToList();

                if (!packingTypes.Any())
                {
                    return Json(new { success = false, message = "No packing types found for this packing master" }, JsonRequestBehavior.AllowGet);
                }

                var fields = packingTypes.Select(pt => new { 
                    label = pt.label, 
                    value = pt.code,
                    id = pt.id
                }).ToList();

                return Json(new { success = true, fields = fields }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        // Get existing product calculation for specific packing master
        public JsonResult GetProductCalculation(int trandid, int packingId)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"Looking for calculation: TRANDID={trandid}, PACKMID={packingId}");
                
                var calculation = db.TransactionProductCalculations
                    .FirstOrDefault(t => t.TRANDID == trandid && t.PACKMID == packingId);
                    
                if (calculation != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Found calculation: TRANPID={calculation.TRANPID}");
                    System.Diagnostics.Debug.WriteLine($"PCK1: {calculation.PCK1}, PCK2: {calculation.PCK2}, PCK3: {calculation.PCK3}");
                    System.Diagnostics.Debug.WriteLine($"PNDSVALUE: {calculation.PNDSVALUE}, YELDPERCENT: {calculation.YELDPERCENT}");
                    System.Diagnostics.Debug.WriteLine($"PRODDATE: {calculation.PRODDATE}");
                    System.Diagnostics.Debug.WriteLine($"CALCULATIONMODE: {calculation.CALCULATIONMODE}");
                    
                    // Create a custom object to ensure proper JSON serialization of dates
                    var result = new
                    {
                        success = true,
                        calculation = new
                        {
                            TRANPID = calculation.TRANPID,
                            TRANDID = calculation.TRANDID,
                            PACKMID = calculation.PACKMID,
                            PCK1 = calculation.PCK1,
                            PCK2 = calculation.PCK2,
                            PCK3 = calculation.PCK3,
                            PCK4 = calculation.PCK4,
                            PCK5 = calculation.PCK5,
                            PCK6 = calculation.PCK6,
                            PCK7 = calculation.PCK7,
                            PCK8 = calculation.PCK8,
                            PCK9 = calculation.PCK9,
                            PCK10 = calculation.PCK10,
                            PCK11 = calculation.PCK11,
                            PCK12 = calculation.PCK12,
                            PCK13 = calculation.PCK13,
                            PCK14 = calculation.PCK14,
                            PCK15 = calculation.PCK15,
                            PCK16 = calculation.PCK16,
                            PCK17 = calculation.PCK17,
                            TOPCK = calculation.TOPCK,
                            PCKLVALUE = calculation.PCKLVALUE,
                            AVGPCKVALUE = calculation.AVGPCKVALUE,
                            PNDSVALUE = calculation.PNDSVALUE,
                            TOTALPNDS = calculation.TOTALPNDS,
                            YELDPERCENT = calculation.YELDPERCENT,
                            TOTALYELDCOUNTS = calculation.TOTALYELDCOUNTS,
                            KGWGT = calculation.KGWGT,
                            PCKKGWGT = calculation.PCKKGWGT,
                            WASTEWGT = calculation.WASTEWGT,
                            WASTEPWGT = calculation.WASTEPWGT,
                            FACTORYWGT = calculation.FACTORYWGT,
                            FACAVGWGT = calculation.FACAVGWGT,
                            FACAVGCOUNT = calculation.FACAVGCOUNT,
                            PRODDATE = calculation.PRODDATE?.ToString("yyyy-MM-dd"), // Format date as string
                            CALCULATIONMODE = calculation.CALCULATIONMODE,
                            GRADEID = calculation.GRADEID,
                            PCLRID = calculation.PCLRID,
                            RCVDTID = calculation.RCVDTID,
                            BKN = calculation.BKN,
                            DISPSTATUS = calculation.DISPSTATUS,
                            CUSRID = calculation.CUSRID,
                            LMUSRID = calculation.LMUSRID,
                            PRCSDATE = calculation.PRCSDATE
                        }
                    };
                    
                    return Json(result, JsonRequestBehavior.AllowGet);
                }
                
                System.Diagnostics.Debug.WriteLine("No calculation found");
                return Json(new { success = false, message = "No calculation found" }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error getting calculation: {ex.Message}");
                return Json(new { success = false, message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        // Save product calculation
        [HttpPost]
        public JsonResult SaveProductCalculation(FormCollection form)
        {
            try
            {
                // Manually parse form data to handle empty strings properly
                var model = ParseFormToModel(form);
                
                // Debug: Log received model data
                System.Diagnostics.Debug.WriteLine($"Received calculation for TRANDID: {model.TRANDID}, PACKMID: {model.PACKMID}");
                System.Diagnostics.Debug.WriteLine($"PCK1: {model.PCK1}, PCK2: {model.PCK2}, PCK3: {model.PCK3}");
                System.Diagnostics.Debug.WriteLine($"PNDSVALUE: {model.PNDSVALUE}, YELDPERCENT: {model.YELDPERCENT}");
                System.Diagnostics.Debug.WriteLine($"KGWGT: {model.KGWGT}, WASTEWGT: {model.WASTEWGT}");
                
                // Sanitize PCK values - ensure null values are properly handled
                SanitizePCKValues(model);
                
                // Check if all PCK values are null
                var pckValues = new[] { model.PCK1, model.PCK2, model.PCK3, model.PCK4, model.PCK5, model.PCK6, 
                                       model.PCK7, model.PCK8, model.PCK9, model.PCK10, model.PCK11, model.PCK12, 
                                       model.PCK13, model.PCK14, model.PCK15, model.PCK16, model.PCK17 };
                var nonNullPcks = pckValues.Where(p => p > 0).ToArray();
                System.Diagnostics.Debug.WriteLine($"Non-zero PCK values: {nonNullPcks.Length}");
                
                if (nonNullPcks.Length == 0)
                {
                    System.Diagnostics.Debug.WriteLine("Warning: All PCK values are null or zero!");
                }
                // Get TRANMID from TRANDID
                var transactionDetail = db.Database.SqlQuery<int>(
                    "SELECT TRANMID FROM TRANSACTIONDETAIL WHERE TRANDID = @p0", model.TRANDID).FirstOrDefault();
                
                if (transactionDetail == 0)
                {
                    return Json(new { success = false, message = "Transaction detail not found" });
                }

                model.TRANMID = transactionDetail;

                // Calculate derived values
                CalculateProductValues(model);

                // Check if record exists for this specific TRANDID and PACKMID combination
                var existing = db.TransactionProductCalculations
                    .FirstOrDefault(t => t.TRANDID == model.TRANDID && t.PACKMID == model.PACKMID);
                
                if (existing != null)
                {
                    // Update existing record
                    UpdateCalculationRecord(existing, model);
                    existing.LMUSRID = User?.Identity?.Name ?? "System";
                    existing.PRCSDATE = DateTime.Now;
                }
                else
                {
                    // Create new record
                    model.CUSRID = User?.Identity?.Name ?? "System";
                    model.LMUSRID = User?.Identity?.Name ?? "System";
                    model.DISPSTATUS = 0;
                    model.PRCSDATE = DateTime.Now;
                    
                    db.TransactionProductCalculations.Add(model);
                }

                db.SaveChanges();
                
                // Return the TRANPID for tracking
                var savedRecord = db.TransactionProductCalculations
                    .FirstOrDefault(t => t.TRANDID == model.TRANDID && t.PACKMID == model.PACKMID);
                
                return Json(new { 
                    success = true, 
                    message = "Calculation saved successfully",
                    tranpid = savedRecord?.TRANPID ?? 0
                });
            }
            catch (System.Data.Entity.Core.EntityCommandExecutionException ex)
            {
                System.Diagnostics.Debug.WriteLine($"EntityCommandExecutionException: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"Inner Exception: {ex.InnerException?.Message}");
                return Json(new { success = false, message = "Database error: " + (ex.InnerException?.Message ?? ex.Message) });
            }
            catch (System.Data.Entity.Validation.DbEntityValidationException ex)
            {
                var errorMessages = ex.EntityValidationErrors
                    .SelectMany(x => x.ValidationErrors)
                    .Select(x => x.ErrorMessage);
                var fullErrorMessage = string.Join("; ", errorMessages);
                System.Diagnostics.Debug.WriteLine($"Validation Error: {fullErrorMessage}");
                return Json(new { success = false, message = "Validation error: " + fullErrorMessage });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"General Exception: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"Stack Trace: {ex.StackTrace}");
                return Json(new { success = false, message = ex.Message });
            }
        }

        private void CalculateProductValues(TransactionProductCalculation model)
        {
            // Calculate TOPCK (sum of all PCK fields + BKN)
            model.TOPCK = model.PCK1 + model.PCK2 + model.PCK3 + model.PCK4 + 
                         model.PCK5 + model.PCK6 + model.PCK7 + model.PCK8 + 
                         model.PCK9 + model.PCK10 + model.PCK11 + model.PCK12 + 
                         model.PCK13 + model.PCK14 + model.PCK15 + model.PCK16 + 
                         model.PCK17 + model.BKN;

            // Check calculation mode to determine which calculations to perform
            bool isGradeWeightMode = model.CALCULATIONMODE == 2;
            System.Diagnostics.Debug.WriteLine($"Calculating in {(isGradeWeightMode ? "Grade Weight" : "Packing")} mode");
            
            if (isGradeWeightMode)
            {
                // Grade Weight mode: Only calculate Slab (TOPCK) and Factory Weight (Slab + Peeled)
                // TOPCK is already calculated above (Slab value)
                
                // Factory Weight = Slab + Peeled (TOPCK + WASTEWGT)
                model.FACTORYWGT = model.TOPCK + model.WASTEWGT;
                
                // Clear other calculated fields for Grade Weight mode
                model.PCKLVALUE = 0;
                model.AVGPCKVALUE = 0;
                model.TOTALPNDS = 0;
                model.TOTALYELDCOUNTS = 0;
                model.PCKKGWGT = 0;
                model.WASTEPWGT = 0;
                
                System.Diagnostics.Debug.WriteLine($"Grade Weight calculation: Slab={model.TOPCK}, Peeled={model.WASTEWGT}, Factory Weight={model.FACTORYWGT}");
            }
            else if (model.TOPCK > 0)
            {
                // Packing mode: Full calculations
                // Calculate PCKLVALUE (multiply each PCK with its corresponding value and sum)
                model.PCKLVALUE = CalculatePCKLValue(model);

                // Calculate AVGPCKVALUE
                model.AVGPCKVALUE = model.PCKLVALUE / model.TOPCK;

                // Calculate TOTALPNDS
                model.TOTALPNDS = model.AVGPCKVALUE * model.PNDSVALUE;

                // Calculate TOTALYELDCOUNTS
                if (model.YELDPERCENT > 0)
                {
                    model.TOTALYELDCOUNTS = model.TOTALPNDS * (model.YELDPERCENT / 100);
                }

                // Calculate PCKKGWGT
                model.PCKKGWGT = model.KGWGT * model.TOPCK;

                // Calculate WASTEPWGT
                model.WASTEPWGT = model.PCKKGWGT + model.WASTEWGT;

                // Calculate FACTORYWGT (Packing mode formula)
                if (model.YELDPERCENT > 0)
                {
                    model.FACTORYWGT = model.WASTEPWGT / (model.YELDPERCENT / 100);
                }
            }
        }

        private decimal CalculatePCKLValue(TransactionProductCalculation model)
        {
            decimal pcklValue = 0;
            var pckValues = new[] { model.PCK1, model.PCK2, model.PCK3, model.PCK4, model.PCK5, model.PCK6, 
                                   model.PCK7, model.PCK8, model.PCK9, model.PCK10, model.PCK11, model.PCK12, 
                                   model.PCK13, model.PCK14, model.PCK15, model.PCK16, model.PCK17 };

            // Get packing types for this packing master (excluding BKN)
            var packingTypes = db.PackingTypeMasters
                .Where(pt => pt.PACKMID == model.PACKMID && pt.DISPSTATUS == 0)
                .OrderBy(pt => pt.PACKTMCODE)
                .ToList();

            if (packingTypes.Any())
            {
                int pckIndex = 0;
                foreach (var packingType in packingTypes)
                {
                    // Check if this is BKN field
                    bool isBKN = packingType.PACKTMDESC.ToUpper().Trim() == "BKN" || 
                                 packingType.PACKTMDESC.ToUpper().Trim() == "BROKEN" || 
                                 packingType.PACKTMDESC.ToUpper().Contains("BKN");
                    
                    if (isBKN)
                    {
                        // Process BKN field separately
                        if (model.BKN > 0)
                        {
                            decimal multiplier = ExtractMultiplierFromDescription(packingType.PACKTMDESC);
                            pcklValue += model.BKN * multiplier;
                        }
                    }
                    else
                    {
                        // Process regular PCK field
                        if (pckIndex < pckValues.Length && pckValues[pckIndex] > 0)
                        {
                            decimal multiplier = ExtractMultiplierFromDescription(packingType.PACKTMDESC);
                            pcklValue += pckValues[pckIndex] * multiplier;
                        }
                        pckIndex++;
                    }
                }
            }

            return pcklValue;
        }

        private decimal ExtractMultiplierFromDescription(string description)
        {
            if (string.IsNullOrEmpty(description))
                return 1;

            // Extract number from descriptions like "U - 5", "U - 10", "51-60", "151-200", etc.
            var numbers = System.Text.RegularExpressions.Regex.Matches(description, @"\d+")
                .Cast<System.Text.RegularExpressions.Match>()
                .Select(m => decimal.Parse(m.Value))
                .ToArray();

            if (numbers.Length == 1)
            {
                // Single number like "U - 5" -> use 5
                return numbers[0];
            }
            else if (numbers.Length == 2)
            {
                // Range like "51-60" -> use the last/highest value (60)
                return numbers[1];
            }

            // Default fallback
            return 1;
        }

        private void UpdateCalculationRecord(TransactionProductCalculation existing, TransactionProductCalculation model)
        {
            existing.PACKMID = model.PACKMID;
            existing.PCK1 = model.PCK1;
            existing.PCK2 = model.PCK2;
            existing.PCK3 = model.PCK3;
            existing.PCK4 = model.PCK4;
            existing.PCK5 = model.PCK5;
            existing.PCK6 = model.PCK6;
            existing.PCK7 = model.PCK7;
            existing.PCK8 = model.PCK8;
            existing.PCK9 = model.PCK9;
            existing.PCK10 = model.PCK10;
            existing.PCK11 = model.PCK11;
            existing.PCK12 = model.PCK12;
            existing.PCK13 = model.PCK13;
            existing.PCK14 = model.PCK14;
            existing.PCK15 = model.PCK15;
            existing.PCK16 = model.PCK16;
            existing.PCK17 = model.PCK17;
            existing.TOPCK = model.TOPCK;
            existing.PCKLVALUE = model.PCKLVALUE;
            existing.AVGPCKVALUE = model.AVGPCKVALUE;
            existing.PNDSVALUE = model.PNDSVALUE;
            existing.TOTALPNDS = model.TOTALPNDS;
            existing.YELDPERCENT = model.YELDPERCENT;
            existing.TOTALYELDCOUNTS = model.TOTALYELDCOUNTS;
            existing.KGWGT = model.KGWGT;
            existing.PCKKGWGT = model.PCKKGWGT;
            existing.WASTEWGT = model.WASTEWGT;
            existing.WASTEPWGT = model.WASTEPWGT;
            existing.FACTORYWGT = model.FACTORYWGT;
            existing.FACAVGWGT = model.FACAVGWGT;
            existing.FACAVGCOUNT = model.FACAVGCOUNT;
            existing.PRODDATE = model.PRODDATE;
            existing.CALCULATIONMODE = model.CALCULATIONMODE;
            existing.GRADEID = model.GRADEID;
            existing.PCLRID = model.PCLRID;
            existing.RCVDTID = model.RCVDTID;
            existing.BKN = model.BKN;
        }

        private TransactionProductCalculation ParseFormToModel(FormCollection form)
        {
            var model = new TransactionProductCalculation();
            
            // Parse required integer fields
            if (int.TryParse(form["TRANPID"], out int tranpid)) model.TRANPID = tranpid;
            if (int.TryParse(form["TRANDID"], out int trandid)) model.TRANDID = trandid;
            if (int.TryParse(form["TRANMID"], out int tranmid)) model.TRANMID = tranmid;
            if (int.TryParse(form["PACKMID"], out int packmid)) model.PACKMID = packmid;
            
            // Parse PCK fields - default to 0 for non-nullable decimals
            model.PCK1 = ParseNullableDecimal(form["PCK1"]) ?? 0;
            model.PCK2 = ParseNullableDecimal(form["PCK2"]) ?? 0;
            model.PCK3 = ParseNullableDecimal(form["PCK3"]) ?? 0;
            model.PCK4 = ParseNullableDecimal(form["PCK4"]) ?? 0;
            model.PCK5 = ParseNullableDecimal(form["PCK5"]) ?? 0;
            model.PCK6 = ParseNullableDecimal(form["PCK6"]) ?? 0;
            model.PCK7 = ParseNullableDecimal(form["PCK7"]) ?? 0;
            model.PCK8 = ParseNullableDecimal(form["PCK8"]) ?? 0;
            model.PCK9 = ParseNullableDecimal(form["PCK9"]) ?? 0;
            model.PCK10 = ParseNullableDecimal(form["PCK10"]) ?? 0;
            model.PCK11 = ParseNullableDecimal(form["PCK11"]) ?? 0;
            model.PCK12 = ParseNullableDecimal(form["PCK12"]) ?? 0;
            model.PCK13 = ParseNullableDecimal(form["PCK13"]) ?? 0;
            model.PCK14 = ParseNullableDecimal(form["PCK14"]) ?? 0;
            model.PCK15 = ParseNullableDecimal(form["PCK15"]) ?? 0;
            model.PCK16 = ParseNullableDecimal(form["PCK16"]) ?? 0;
            model.PCK17 = ParseNullableDecimal(form["PCK17"]) ?? 0;
            
            // Parse other decimal fields - default to 0 for non-nullable decimals
            model.PNDSVALUE = ParseNullableDecimal(form["PNDSVALUE"]) ?? 0;
            model.YELDPERCENT = ParseNullableDecimal(form["YELDPERCENT"]) ?? 0;
            model.KGWGT = ParseNullableDecimal(form["KGWGT"]) ?? 0;
            model.WASTEWGT = ParseNullableDecimal(form["WASTEWGT"]) ?? 0;
            model.FACAVGWGT = ParseNullableDecimal(form["FACAVGWGT"]) ?? 0;
            model.FACAVGCOUNT = ParseNullableDecimal(form["FACAVGCOUNT"]) ?? 0;
            
            // Parse BKN field (Broken) - default to 0 for non-nullable decimal
            model.BKN = ParseNullableDecimal(form["BKN"]) ?? 0;
            
            // Parse PRODDATE field
            model.PRODDATE = ParseNullableDateTime(form["PRODDATE"]);
            
            // Parse CALCULATIONMODE field - Convert frontend string to backend integer
            var calculationModeString = form["CalculationMode"] ?? "packing";
            model.CALCULATIONMODE = calculationModeString == "gradeweight" ? 2 : 1; // 1=Packing, 2=Grade Weight
            
            // Parse new dropdown fields (not required, default to 0)
            model.GRADEID = ParseNullableInt(form["GRADEID"]) ?? 0;
            model.PCLRID = ParseNullableInt(form["PCLRID"]) ?? 0;
            model.RCVDTID = ParseNullableInt(form["RCVDTID"]) ?? 0;
            
            System.Diagnostics.Debug.WriteLine($"Parsed model - TRANDID: {model.TRANDID}, PACKMID: {model.PACKMID}");
            System.Diagnostics.Debug.WriteLine($"Parsed PCK1: '{form["PCK1"]}' -> {model.PCK1}");
            System.Diagnostics.Debug.WriteLine($"Parsed PCK2: '{form["PCK2"]}' -> {model.PCK2}");
            System.Diagnostics.Debug.WriteLine($"Parsed PCK3: '{form["PCK3"]}' -> {model.PCK3}");
            System.Diagnostics.Debug.WriteLine($"Parsed BKN: '{form["BKN"]}' -> {model.BKN}");
            System.Diagnostics.Debug.WriteLine($"Parsed GRADEID: '{form["GRADEID"]}' -> {model.GRADEID}");
            System.Diagnostics.Debug.WriteLine($"Parsed PCLRID: '{form["PCLRID"]}' -> {model.PCLRID}");
            System.Diagnostics.Debug.WriteLine($"Parsed RCVDTID: '{form["RCVDTID"]}' -> {model.RCVDTID}");
            
            return model;
        }
        
        private decimal? ParseNullableDecimal(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;
                
            if (decimal.TryParse(value, out decimal result))
                return result;
                
            return null;
        }
        
        private DateTime? ParseNullableDateTime(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;
                
            if (DateTime.TryParse(value, out DateTime result))
                return result;
                
            return null;
        }
        
        private int? ParseNullableInt(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;
                
            if (int.TryParse(value, out int result))
                return result;
                
            return null;
        }

        private void SanitizePCKValues(TransactionProductCalculation model)
        {
            // Ensure all PCK values are properly null if they are zero or invalid
            // This prevents EntityCommandExecutionException when saving to database
            
            // PCK fields are now non-nullable with default value 0
            // No need to convert 0 to null anymore
            
            // Don't convert these to null as they might legitimately be 0
            // Only convert if they are exactly 0 and we want to store null instead
            // Keep PNDSVALUE, YELDPERCENT, KGWGT, WASTEWGT as they are since 0 might be valid
            
            // Ensure required fields have valid values
            if (model.TRANDID <= 0)
            {
                throw new ArgumentException("TRANDID is required and must be greater than 0");
            }
            
            if (model.PACKMID <= 0)
            {
                throw new ArgumentException("PACKMID is required and must be greater than 0");
            }
            
            System.Diagnostics.Debug.WriteLine("PCK values sanitized - zero values converted to null");
        }

        // Quality Check Methods
        public JsonResult CheckQualityCheckTable()
        {
            try
            {
                // Test if the table exists by trying to query it
                var count = db.Database.SqlQuery<int>("SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME = 'TRANSACTION_QUALITY_CHECK'").FirstOrDefault();
                
                if (count == 0)
                {
                    return Json(new { 
                        success = false, 
                        message = "TRANSACTION_QUALITY_CHECK table does not exist. Please run the database script to create it.",
                        tableExists = false
                    }, JsonRequestBehavior.AllowGet);
                }
                
                return Json(new { 
                    success = true, 
                    message = "Table exists",
                    tableExists = true
                }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { 
                    success = false, 
                    message = ex.Message,
                    tableExists = false
                }, JsonRequestBehavior.AllowGet);
            }
        }

        public JsonResult CheckTransactionExists(int tranmid)
        {
            try
            {
                // Check if TRANMID exists in TRANSACTIONMASTER
                var exists = db.Database.SqlQuery<int>("SELECT COUNT(*) FROM TRANSACTIONMASTER WHERE TRANMID = @p0", tranmid).FirstOrDefault();
                
                if (exists > 0)
                {
                    // Get transaction details
                    var transaction = db.Database.SqlQuery<dynamic>("SELECT TRANMID, TRANDATE, CATENAME, CATECODE FROM TRANSACTIONMASTER WHERE TRANMID = @p0", tranmid).FirstOrDefault();
                    
                    return Json(new { 
                        success = true, 
                        exists = true,
                        message = $"Transaction {tranmid} exists",
                        transaction = transaction
                    }, JsonRequestBehavior.AllowGet);
                }
                else
                {
                    // Get available TRANMIDs
                    var availableIds = db.Database.SqlQuery<int>("SELECT TOP 10 TRANMID FROM TRANSACTIONMASTER ORDER BY TRANMID DESC").ToList();
                    
                    return Json(new { 
                        success = false, 
                        exists = false,
                        message = $"Transaction {tranmid} does not exist",
                        availableIds = availableIds
                    }, JsonRequestBehavior.AllowGet);
                }
            }
            catch (Exception ex)
            {
                return Json(new { 
                    success = false, 
                    message = $"Error checking transaction: {ex.Message}"
                }, JsonRequestBehavior.AllowGet);
            }
        }

        public JsonResult TestQualityCheckInsert(int tranmid)
        {
            try
            {
                // First check if TRANMID exists
                var transactionExists = db.Database.SqlQuery<int>("SELECT COUNT(*) FROM TRANSACTIONMASTER WHERE TRANMID = @p0", tranmid).FirstOrDefault();
                if (transactionExists == 0)
                {
                    return Json(new { 
                        success = false, 
                        message = $"Cannot insert: TRANMID {tranmid} does not exist in TRANSACTIONMASTER table"
                    }, JsonRequestBehavior.AllowGet);
                }

                // Try to insert a test record using raw SQL to bypass Entity Framework
                var sql = @"
                    INSERT INTO TRANSACTION_QUALITY_CHECK 
                    (TRANMID, LABOID, STATUS, REMARKS, DONEBY, VERIFIEDBY, LOTDATE, CUSRID, LMUSRID, DISPSTATUS, PRCSDATE)
                    VALUES 
                    (@p0, @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10)";
                
                var result = db.Database.ExecuteSqlCommand(sql, 
                    tranmid,           // TRANMID
                    1,                 // LABOID (assuming lab with ID 1 exists)
                    0,                 // STATUS
                    "Test remarks",    // REMARKS
                    "Test User",       // DONEBY
                    "Test Verifier",   // VERIFIEDBY
                    DateTime.Now,      // LOTDATE
                    "System",          // CUSRID
                    "System",          // LMUSRID
                    0,                 // DISPSTATUS
                    DateTime.Now       // PRCSDATE
                );
                
                return Json(new { 
                    success = true, 
                    message = $"Test insert successful. Rows affected: {result}"
                }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { 
                    success = false, 
                    message = $"Test insert failed: {ex.Message}"
                }, JsonRequestBehavior.AllowGet);
            }
        }

        public JsonResult GetLaboratories()
        {
            try
            {
                var laboratories = db.LaboratoryMasters
                    .Where(l => l.DISPSTATUS == 0)
                    .OrderBy(l => l.LABODESC)
                    .Select(l => new { id = l.LABOID, text = l.LABODESC })
                    .ToList();
                return Json(laboratories, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { error = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        public JsonResult GetQualityCheck(int tranmid)
        {
            try
            {
                var qualityCheck = db.TransactionQualityChecks
                    .FirstOrDefault(q => q.TRANMID == tranmid);
                    
                if (qualityCheck != null)
                {
                    return Json(new { 
                        success = true, 
                        data = new {
                            TRANQID = qualityCheck.TRANQID,
                            TRANMID = qualityCheck.TRANMID,
                            LABOID = qualityCheck.LABOID,
                            STATUS = qualityCheck.STATUS,
                            REMARKS = qualityCheck.REMARKS,
                            DONEBY = qualityCheck.DONEBY,
                            VERIFIEDBY = qualityCheck.VERIFIEDBY,
                            LOTDATE = qualityCheck.LOTDATE.ToString("yyyy-MM-dd")
                        }
                    }, JsonRequestBehavior.AllowGet);
                }
                
                return Json(new { success = false, message = "No quality check found" }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        [HttpPost]
        public JsonResult SaveQualityCheckRawSQL(FormCollection form)
        {
            try
            {
                var tranmid = int.Parse(form["TRANMID"]);
                var laboid = int.Parse(form["LABOID"]);
                var status = int.Parse(form["STATUS"]);
                var remarks = form["REMARKS"]?.Trim();
                var doneby = form["DONEBY"]?.Trim();
                var verifiedby = form["VERIFIEDBY"]?.Trim();
                var lotdate = DateTime.Parse(form["LOTDATE"]);
                
                System.Diagnostics.Debug.WriteLine($"SaveQualityCheckRawSQL called with TRANMID: {tranmid}");
                
                // First check if TRANMID exists in TRANSACTIONMASTER
                var transactionExists = db.Database.SqlQuery<int>("SELECT COUNT(*) FROM TRANSACTIONMASTER WHERE TRANMID = @p0", tranmid).FirstOrDefault();
                if (transactionExists == 0)
                {
                    var availableIds = db.Database.SqlQuery<int>("SELECT TOP 5 TRANMID FROM TRANSACTIONMASTER ORDER BY TRANMID DESC").ToList();
                    return Json(new { 
                        success = false, 
                        message = $"Transaction {tranmid} does not exist in TRANSACTIONMASTER. Available IDs: {string.Join(", ", availableIds)}"
                    });
                }
                
                // Check if record exists
                var existingCount = db.Database.SqlQuery<int>("SELECT COUNT(*) FROM TRANSACTION_QUALITY_CHECK WHERE TRANMID = @p0", tranmid).FirstOrDefault();
                
                if (existingCount > 0)
                {
                    // Update
                    var updateSql = @"
                        UPDATE TRANSACTION_QUALITY_CHECK 
                        SET LABOID = @p1, STATUS = @p2, REMARKS = @p3, DONEBY = @p4, VERIFIEDBY = @p5, 
                            LOTDATE = @p6, LMUSRID = @p7, PRCSDATE = @p8
                        WHERE TRANMID = @p0";
                    
                    var result = db.Database.ExecuteSqlCommand(updateSql, 
                        tranmid, laboid, status, remarks, doneby, verifiedby, lotdate, 
                        User?.Identity?.Name ?? "System", DateTime.Now);
                    
                    return Json(new { success = true, message = "Quality check updated successfully" });
                }
                else
                {
                    // Insert
                    var insertSql = @"
                        INSERT INTO TRANSACTION_QUALITY_CHECK 
                        (TRANMID, LABOID, STATUS, REMARKS, DONEBY, VERIFIEDBY, LOTDATE, CUSRID, LMUSRID, DISPSTATUS, PRCSDATE)
                        VALUES 
                        (@p0, @p1, @p2, @p3, @p4, @p5, @p6, @p7, @p8, @p9, @p10)";
                    
                    var result = db.Database.ExecuteSqlCommand(insertSql, 
                        tranmid, laboid, status, remarks, doneby, verifiedby, lotdate,
                        User?.Identity?.Name ?? "System", User?.Identity?.Name ?? "System", 0, DateTime.Now);
                    
                    return Json(new { success = true, message = "Quality check saved successfully" });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"SaveQualityCheckRawSQL Exception: {ex.Message}");
                return Json(new { success = false, message = ex.Message });
            }
        }

        [HttpPost]
        public JsonResult SaveQualityCheck(TransactionQualityCheck model)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"SaveQualityCheck called with TRANMID: {model.TRANMID}");
                
                if (model.TRANMID <= 0)
                {
                    return Json(new { success = false, message = "Invalid Transaction Master ID" });
                }

                // Validate required fields
                if (model.LABOID <= 0)
                {
                    return Json(new { success = false, message = "Laboratory is required" });
                }

                // Check if TRANMID exists in TRANSACTIONMASTER
                var transactionExists = db.TransactionMasters.Any(t => t.TRANMID == model.TRANMID);
                if (!transactionExists)
                {
                    return Json(new { success = false, message = $"Transaction Master with ID {model.TRANMID} does not exist" });
                }

                // Check if LABOID exists in LABORATORYMASTER
                var laboratoryExists = db.LaboratoryMasters.Any(l => l.LABOID == model.LABOID);
                if (!laboratoryExists)
                {
                    return Json(new { success = false, message = $"Laboratory with ID {model.LABOID} does not exist" });
                }

                if (string.IsNullOrWhiteSpace(model.REMARKS))
                {
                    return Json(new { success = false, message = "Remarks is required" });
                }

                if (string.IsNullOrWhiteSpace(model.DONEBY))
                {
                    return Json(new { success = false, message = "Done By is required" });
                }

                if (string.IsNullOrWhiteSpace(model.VERIFIEDBY))
                {
                    return Json(new { success = false, message = "Verified By is required" });
                }

                // Validate LOTDATE
                if (model.LOTDATE == DateTime.MinValue)
                {
                    return Json(new { success = false, message = "Date is required" });
                }

                // Validate string lengths
                if (model.DONEBY?.Length > 100)
                {
                    return Json(new { success = false, message = "Done By cannot exceed 100 characters" });
                }

                if (model.VERIFIEDBY?.Length > 100)
                {
                    return Json(new { success = false, message = "Verified By cannot exceed 100 characters" });
                }

                // Check if record exists
                var existing = db.TransactionQualityChecks
                    .FirstOrDefault(q => q.TRANMID == model.TRANMID);
                
                if (existing != null)
                {
                    System.Diagnostics.Debug.WriteLine($"Updating existing quality check record: {existing.TRANQID}");
                    
                    // Update existing record
                    existing.LABOID = model.LABOID;
                    existing.STATUS = model.STATUS;
                    existing.REMARKS = model.REMARKS?.Trim();
                    existing.DONEBY = model.DONEBY?.Trim();
                    existing.VERIFIEDBY = model.VERIFIEDBY?.Trim();
                    existing.LOTDATE = model.LOTDATE;
                    existing.LMUSRID = User?.Identity?.Name ?? "System";
                    existing.PRCSDATE = DateTime.Now;
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine("Creating new quality check record");
                    
                    // Create new record
                    model.CUSRID = User?.Identity?.Name ?? "System";
                    model.LMUSRID = User?.Identity?.Name ?? "System";
                    model.DISPSTATUS = 0;
                    model.PRCSDATE = DateTime.Now;
                    
                    // Trim string fields
                    model.REMARKS = model.REMARKS?.Trim();
                    model.DONEBY = model.DONEBY?.Trim();
                    model.VERIFIEDBY = model.VERIFIEDBY?.Trim();
                    
                    // Debug log the data being saved
                    System.Diagnostics.Debug.WriteLine($"Quality Check Data:");
                    System.Diagnostics.Debug.WriteLine($"  TRANMID: {model.TRANMID}");
                    System.Diagnostics.Debug.WriteLine($"  LABOID: {model.LABOID}");
                    System.Diagnostics.Debug.WriteLine($"  STATUS: {model.STATUS}");
                    System.Diagnostics.Debug.WriteLine($"  REMARKS: '{model.REMARKS}' (Length: {model.REMARKS?.Length ?? 0})");
                    System.Diagnostics.Debug.WriteLine($"  DONEBY: '{model.DONEBY}' (Length: {model.DONEBY?.Length ?? 0})");
                    System.Diagnostics.Debug.WriteLine($"  VERIFIEDBY: '{model.VERIFIEDBY}' (Length: {model.VERIFIEDBY?.Length ?? 0})");
                    System.Diagnostics.Debug.WriteLine($"  LOTDATE: {model.LOTDATE}");
                    System.Diagnostics.Debug.WriteLine($"  CUSRID: '{model.CUSRID}'");
                    System.Diagnostics.Debug.WriteLine($"  LMUSRID: '{model.LMUSRID}'");
                    System.Diagnostics.Debug.WriteLine($"  DISPSTATUS: {model.DISPSTATUS}");
                    System.Diagnostics.Debug.WriteLine($"  PRCSDATE: {model.PRCSDATE}");
                    
                    db.TransactionQualityChecks.Add(model);
                }

                db.SaveChanges();
                System.Diagnostics.Debug.WriteLine("Quality check saved successfully");
                
                return Json(new { 
                    success = true, 
                    message = "Quality check saved successfully"
                });
            }
            catch (System.Data.Entity.Infrastructure.DbUpdateException ex)
            {
                System.Diagnostics.Debug.WriteLine($"DbUpdateException: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"Inner Exception: {ex.InnerException?.Message}");
                
                // Get the deepest inner exception
                Exception innermost = ex;
                while (innermost.InnerException != null)
                {
                    innermost = innermost.InnerException;
                    System.Diagnostics.Debug.WriteLine($"Deeper Inner Exception: {innermost.Message}");
                }
                
                var errorMessage = "Database error occurred. ";
                var innermostMessage = innermost.Message;
                
                if (innermostMessage.Contains("Invalid object name 'dbo.TRANSACTION_QUALITY_CHECK'"))
                {
                    errorMessage += "The TRANSACTION_QUALITY_CHECK table does not exist. Please run the database script to create it.";
                }
                else if (innermostMessage.Contains("foreign key constraint") || innermostMessage.Contains("FOREIGN KEY"))
                {
                    errorMessage += "Foreign key constraint violation. Please check if the referenced records exist.";
                }
                else if (innermostMessage.Contains("Cannot insert the value NULL"))
                {
                    errorMessage += "Required field is missing or null: " + innermostMessage;
                }
                else if (innermostMessage.Contains("String or binary data would be truncated"))
                {
                    errorMessage += "Data too long for field: " + innermostMessage;
                }
                else
                {
                    errorMessage += innermostMessage;
                }
                
                return Json(new { success = false, message = errorMessage });
            }
            catch (System.Data.Entity.Validation.DbEntityValidationException ex)
            {
                var errorMessages = ex.EntityValidationErrors
                    .SelectMany(x => x.ValidationErrors)
                    .Select(x => x.ErrorMessage);
                var fullErrorMessage = string.Join("; ", errorMessages);
                System.Diagnostics.Debug.WriteLine($"Validation Error: {fullErrorMessage}");
                return Json(new { success = false, message = "Validation error: " + fullErrorMessage });
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"General Exception: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"Stack Trace: {ex.StackTrace}");
                return Json(new { success = false, message = "Unexpected error: " + ex.Message });
            }
        }


        // Test method to check if controller is accessible
        public ActionResult TestPDF()
        {
            return Content("PDF Controller is working! Current time: " + DateTime.Now.ToString());
        }

        // Helper class for PDF transaction details
        public class PDFTransactionDetail
        {
            public int TRANDID { get; set; }
            public int TRANMID { get; set; }
            public int MTRLGID { get; set; }
            public int MTRLID { get; set; }
            public int MTRLNBOX { get; set; }
            public int MTRLCOUNTS { get; set; }
            public string ProductType { get; set; }
            public string Product { get; set; }
        }

        // Direct PDF Generation Methods
        public ActionResult GenerateCalculationPDF(int tranmid)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[PDF] GenerateCalculationPDF called with tranmid: {tranmid}");
                
                // Get transaction master details
                var transaction = db.TransactionMasters.FirstOrDefault(t => t.TRANMID == tranmid);
                if (transaction == null)
                {
                    return HttpNotFound("Transaction not found");
                }

                // Get transaction details with products
                var transactionDetails = db.Database.SqlQuery<PDFTransactionDetail>(@"
                    SELECT td.TRANDID, td.MTRLGID, td.MTRLID, td.MTRLNBOX, td.MTRLCOUNTS,
                           mg.MTRLGDESC as ProductType, m.MTRLDESC as Product
                    FROM TRANSACTIONDETAIL td
                    INNER JOIN MATERIALGROUPMASTER mg ON mg.MTRLGID = td.MTRLGID
                    INNER JOIN MATERIALMASTER m ON m.MTRLID = td.MTRLID
                    WHERE td.TRANMID = @p0
                    ORDER BY td.TRANDID", tranmid).ToList();

                System.Diagnostics.Debug.WriteLine($"[PDF] Found {transactionDetails.Count} transaction details");

                // Get all calculations for this transaction
                var allCalculations = db.TransactionProductCalculations
                    .Where(c => c.TRANMID == tranmid)
                    .ToList();

                System.Diagnostics.Debug.WriteLine($"[PDF] Found {allCalculations.Count} calculations");

                // Group calculations by TRANDID
                var calculationsByTrandid = allCalculations.GroupBy(c => c.TRANDID).ToList();

                // Generate HTML content for PDF
                var htmlContent = GeneratePDFContent(transaction, transactionDetails, calculationsByTrandid);

                System.Diagnostics.Debug.WriteLine($"[PDF] Generated HTML content length: {htmlContent.Length}");

                // Return HTML content as a view result for PDF generation
                ViewBag.HtmlContent = htmlContent;
                return View("PDFView");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PDF] Error generating PDF: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[PDF] Stack trace: {ex.StackTrace}");
                
                // Return an error page instead of JSON for better debugging
                ViewBag.ErrorMessage = $"Error generating PDF: {ex.Message}";
                ViewBag.HtmlContent = $@"
                    <html>
                    <head><title>PDF Generation Error</title></head>
                    <body>
                        <h1>PDF Generation Error</h1>
                        <p><strong>Error:</strong> {ex.Message}</p>
                        <p><strong>Transaction ID:</strong> {tranmid}</p>
                        <p><strong>Time:</strong> {DateTime.Now}</p>
                        <hr>
                        <p>Please check the console logs for more details.</p>
                    </body>
                    </html>";
                return View("PDFView");
            }
        }

        // Generate PDF for specific TRANDID (single row)
        public ActionResult GenerateRowCalculationPDF(int trandid)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[PDF] GenerateRowCalculationPDF called with trandid: {trandid}");
                
                // Get transaction detail for this TRANDID
                var transactionDetail = db.Database.SqlQuery<PDFTransactionDetail>(@"
                    SELECT td.TRANDID, td.TRANMID, td.MTRLGID, td.MTRLID, td.MTRLNBOX, td.MTRLCOUNTS,
                           mg.MTRLGDESC as ProductType, m.MTRLDESC as Product
                    FROM TRANSACTIONDETAIL td
                    INNER JOIN MATERIALGROUPMASTER mg ON mg.MTRLGID = td.MTRLGID
                    INNER JOIN MATERIALMASTER m ON m.MTRLID = td.MTRLID
                    WHERE td.TRANDID = @p0", trandid).FirstOrDefault();

                if (transactionDetail == null)
                {
                    return HttpNotFound("Transaction detail not found");
                }

                // Get transaction master details
                var transaction = db.TransactionMasters.FirstOrDefault(t => t.TRANMID == transactionDetail.TRANMID);
                if (transaction == null)
                {
                    return HttpNotFound("Transaction master not found");
                }

                // Get calculations for this specific TRANDID
                var calculations = db.TransactionProductCalculations
                    .Where(c => c.TRANDID == trandid)
                    .ToList();

                System.Diagnostics.Debug.WriteLine($"[PDF] Found {calculations.Count} calculations for TRANDID {trandid}");

                // Generate HTML content for PDF
                var htmlContent = GenerateRowPDFContent(transaction, transactionDetail, calculations);

                System.Diagnostics.Debug.WriteLine($"[PDF] Generated HTML content length: {htmlContent.Length}");

                // Return HTML content as a view result for PDF generation
                ViewBag.HtmlContent = htmlContent;
                return View("PDFView");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[PDF] Error generating row PDF: {ex.Message}");
                System.Diagnostics.Debug.WriteLine($"[PDF] Stack trace: {ex.StackTrace}");
                
                // Return an error page instead of JSON for better debugging
                ViewBag.ErrorMessage = $"Error generating PDF: {ex.Message}";
                ViewBag.HtmlContent = $@"
                    <html>
                    <head><title>PDF Generation Error</title></head>
                    <body>
                        <h1>PDF Generation Error</h1>
                        <p><strong>Error:</strong> {ex.Message}</p>
                        <p><strong>Transaction Detail ID:</strong> {trandid}</p>
                        <p><strong>Time:</strong> {DateTime.Now}</p>
                        <hr>
                        <p>Please check the console logs for more details.</p>
                    </body>
                    </html>";
                return View("PDFView");
            }
        }

        private string GenerateRowPDFContent(TransactionMaster transaction, PDFTransactionDetail transactionDetail, 
            List<TransactionProductCalculation> calculations)
        {
            var html = $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>Product Calculation Report - Single Row</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.4; }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 20px; page-break-inside: avoid; }}
        .table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; }}
        .table th, .table td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
        .table th {{ background-color: #f8f9fa; font-weight: bold; }}
        .page-break {{ page-break-before: always; }}
        .calculation-header {{ background-color: #e9ecef; padding: 10px; margin: 10px 0; font-weight: bold; }}
        .packing-section {{ margin: 15px 0; }}
        .calculation-section {{ margin: 15px 0; }}
        .value {{ font-weight: bold; color: #007bff; }}
        h2 {{ color: #333; margin-bottom: 5px; }}
        h3 {{ color: #666; margin-bottom: 10px; }}
        h4 {{ color: #333; margin-bottom: 8px; }}
        .transaction-info {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .no-calculations {{ text-align: center; color: #666; font-style: italic; padding: 20px; }}
    </style>
</head>
<body>
    <div class='header'>
        <h2>MARINEX - Product Calculation Report</h2>
        <h3>Raw Material Intake - Single Product Calculation</h3>
    </div>
    
    <div class='transaction-info'>
        <h4>Transaction Information</h4>
        <table class='table'>
            <tr><th>Transaction ID:</th><td>{transaction.TRANMID}</td></tr>
            <tr><th>Transaction Date:</th><td>{transaction.TRANDATE:dd/MM/yyyy}</td></tr>
            <tr><th>Supplier Name:</th><td>{transaction.CATENAME ?? "N/A"}</td></tr>
            <tr><th>Supplier Code:</th><td>{transaction.CATECODE ?? "N/A"}</td></tr>
            <tr><th>Vehicle No:</th><td>{transaction.VECHNO ?? "N/A"}</td></tr>
            <tr><th>Client Weight (KG):</th><td>{transaction.CLIENTWGHT:F3}</td></tr>
        </table>
        
        <h4>Product Information</h4>
        <table class='table'>
            <tr><th>Product Type:</th><td>{transactionDetail.ProductType}</td></tr>
            <tr><th>Product:</th><td>{transactionDetail.Product}</td></tr>
            <tr><th>No. of Boxes:</th><td>{transactionDetail.MTRLNBOX}</td></tr>
            <tr><th>Count (Per KG):</th><td>{transactionDetail.MTRLCOUNTS}</td></tr>
            <tr><th>Report Generated:</th><td>{DateTime.Now:dd/MM/yyyy HH:mm:ss}</td></tr>
        </table>
    </div>";

            // Add calculations for this specific product
            if (calculations != null && calculations.Any())
            {
                // Group by packing master
                var packingGroups = calculations.GroupBy(c => c.PACKMID);
                
                foreach (var packingGroup in packingGroups)
                {
                    var packingId = packingGroup.Key;
                    var calculation = packingGroup.First();
                    
                    // Get packing master name
                    var packingMaster = db.PackingMasters.FirstOrDefault(p => p.PACKMID == packingId);
                    var packingName = packingMaster?.PACKMDESC ?? $"Packing {packingId}";

                    html += $@"
    <div class='section'>
        <div class='calculation-header'>
            {packingName} Calculation
        </div>
        
        <div class='packing-section'>";

                    // Add production date if available
                    if (calculation.PRODDATE.HasValue)
                    {
                        html += $@"
            <p><strong>Production Date:</strong> {calculation.PRODDATE.Value:dd/MM/yyyy}</p>";
                    }

                    // Add calculation mode
                    var calculationMode = calculation.CALCULATIONMODE == 2 ? "Grade Weight Mode" : "Packing Mode";
                    html += $@"
            <p><strong>Calculation Mode:</strong> {calculationMode}</p>";

                    // Get packing type fields for this packing master
                    var packingFields = GetPackingTypeFieldsForPDF(packingId);
                    
                    // Display packing details
                    html += $@"
            <div class='calculation-section'>
                <h5>Packing Details</h5>
                <table class='table'>
                    <tr><th>Slab Size</th><th>Count</th></tr>";

                    var pckValues = new[] { 
                        calculation.PCK1, calculation.PCK2, calculation.PCK3, calculation.PCK4, 
                        calculation.PCK5, calculation.PCK6, calculation.PCK7, calculation.PCK8, 
                        calculation.PCK9, calculation.PCK10, calculation.PCK11, calculation.PCK12, 
                        calculation.PCK13, calculation.PCK14, calculation.PCK15, calculation.PCK16, 
                        calculation.PCK17 
                    };

                    for (int i = 0; i < pckValues.Length && i < packingFields.Count; i++)
                    {
                        if (pckValues[i] > 0)
                        {
                            html += $@"
                    <tr><td>{packingFields[i]}</td><td class='value'>{pckValues[i]:F3}</td></tr>";
                        }
                    }

                    html += $@"
                    <tr style='background-color: #e9ecef;'><th>Total (Slab):</th><th class='value'>{calculation.TOPCK:F3}</th></tr>
                </table>
            </div>";

                    // Display calculation results based on mode
                    if (calculation.CALCULATIONMODE == 2) // Grade Weight Mode
                    {
                        html += $@"
            <div class='calculation-section'>
                <h5>Grade Weight Calculation</h5>
                <table class='table'>
                    <tr><th>Slab:</th><td class='value'>{calculation.TOPCK:F3}</td></tr>
                    <tr><th>Peeled:</th><td class='value'>{calculation.WASTEWGT:F3}</td></tr>
                    <tr style='background-color: #e9ecef;'><th>Factory Weight:</th><th class='value'>{calculation.FACTORYWGT:F3}</th></tr>
                </table>
            </div>";
                    }
                    else // Packing Mode
                    {
                        html += $@"
            <div class='calculation-section'>
                <h5>Slab Calculation</h5>
                <table class='table'>
                    <tr><th>Total PCK:</th><td class='value'>{calculation.TOPCK:F3}</td></tr>
                    <tr><th>PCK L Value:</th><td class='value'>{calculation.PCKLVALUE:F3}</td></tr>
                    <tr><th>Avg PCK Value:</th><td class='value'>{calculation.AVGPCKVALUE:F3}</td></tr>
                    <tr><th>PNDS Value:</th><td class='value'>{calculation.PNDSVALUE:F3}</td></tr>
                    <tr><th>Total PNDS:</th><td class='value'>{calculation.TOTALPNDS:F3}</td></tr>
                </table>
            </div>

            <div class='calculation-section'>
                <h5>Total Weight Calculation</h5>
                <table class='table'>
                    <tr><th>Yield Percent:</th><td class='value'>{calculation.YELDPERCENT:F3}%</td></tr>
                    <tr><th>Total Yield Counts:</th><td class='value'>{calculation.TOTALYELDCOUNTS:F3}</td></tr>
                    <tr><th>KG Weight:</th><td class='value'>{calculation.KGWGT:F3}</td></tr>
                    <tr><th>PCK KG Weight:</th><td class='value'>{calculation.PCKKGWGT:F3}</td></tr>
                    <tr><th>Waste Weight:</th><td class='value'>{calculation.WASTEWGT:F3}</td></tr>
                    <tr><th>Waste P Weight:</th><td class='value'>{calculation.WASTEPWGT:F3}</td></tr>
                    <tr style='background-color: #e9ecef;'><th>Factory Weight:</th><th class='value'>{calculation.FACTORYWGT:F3}</th></tr>
                </table>
            </div>";
                    }

                    html += @"
        </div>
    </div>"; // End section
                }
            }
            else
            {
                html += @"
    <div class='section'>
        <div class='no-calculations'>No calculations available for this product.</div>
    </div>";
            }

            html += @"
</body>
</html>";

            return html;
        }

        private string GeneratePDFContent(TransactionMaster transaction, List<PDFTransactionDetail> transactionDetails, 
            IEnumerable<IGrouping<int, TransactionProductCalculation>> calculationsByTrandid)
        {
            var html = $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>Product Calculation Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; line-height: 1.4; }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 10px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 20px; page-break-inside: avoid; }}
        .table {{ width: 100%; border-collapse: collapse; margin-bottom: 15px; }}
        .table th, .table td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
        .table th {{ background-color: #f8f9fa; font-weight: bold; }}
        .page-break {{ page-break-before: always; }}
        .calculation-header {{ background-color: #e9ecef; padding: 10px; margin: 10px 0; font-weight: bold; }}
        .packing-section {{ margin: 15px 0; }}
        .calculation-section {{ margin: 15px 0; }}
        .value {{ font-weight: bold; color: #007bff; }}
        h2 {{ color: #333; margin-bottom: 5px; }}
        h3 {{ color: #666; margin-bottom: 10px; }}
        h4 {{ color: #333; margin-bottom: 8px; }}
        .transaction-info {{ background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .no-calculations {{ text-align: center; color: #666; font-style: italic; padding: 20px; }}
    </style>
</head>
<body>
    <div class='header'>
        <h2>MARINEX - Product Calculation Report</h2>
        <h3>Raw Material Intake Calculation Details</h3>
    </div>
    
    <div class='transaction-info'>
        <h4>Transaction Information</h4>
        <table class='table'>
            <tr><th>Transaction ID:</th><td>{transaction.TRANMID}</td></tr>
            <tr><th>Transaction Date:</th><td>{transaction.TRANDATE:dd/MM/yyyy}</td></tr>
            <tr><th>Supplier Name:</th><td>{transaction.CATENAME ?? "N/A"}</td></tr>
            <tr><th>Supplier Code:</th><td>{transaction.CATECODE ?? "N/A"}</td></tr>
            <tr><th>Vehicle No:</th><td>{transaction.VECHNO ?? "N/A"}</td></tr>
            <tr><th>Client Weight (KG):</th><td>{transaction.CLIENTWGHT:F3}</td></tr>
            <tr><th>Report Generated:</th><td>{DateTime.Now:dd/MM/yyyy HH:mm:ss}</td></tr>
        </table>
    </div>";

            // Add calculations for each transaction detail
            foreach (var detail in transactionDetails)
            {
                var trandid = detail.TRANDID;
                var productType = detail.ProductType;
                var product = detail.Product;
                var boxes = detail.MTRLNBOX;
                var counts = detail.MTRLCOUNTS;

                html += $@"
    <div class='section'>
        <div class='calculation-header'>
            Product: {product} ({productType}) - Boxes: {boxes}, Count: {counts}
        </div>";

                // Get calculations for this TRANDID
                var calculations = calculationsByTrandid.FirstOrDefault(g => g.Key == trandid);
                if (calculations != null && calculations.Any())
                {
                    // Group by packing master
                    var packingGroups = calculations.GroupBy(c => c.PACKMID);
                    
                    foreach (var packingGroup in packingGroups)
                    {
                        var packingId = packingGroup.Key;
                        var calculation = packingGroup.First();
                        
                        // Get packing master name
                        var packingMaster = db.PackingMasters.FirstOrDefault(p => p.PACKMID == packingId);
                        var packingName = packingMaster?.PACKMDESC ?? $"Packing {packingId}";

                        html += $@"
        <div class='packing-section'>
            <h4>{packingName} Calculation</h4>";

                        // Add production date if available
                        if (calculation.PRODDATE.HasValue)
                        {
                            html += $@"
            <p><strong>Production Date:</strong> {calculation.PRODDATE.Value:dd/MM/yyyy}</p>";
                        }

                        // Add calculation mode
                        var calculationMode = calculation.CALCULATIONMODE == 2 ? "Grade Weight Mode" : "Packing Mode";
                        html += $@"
            <p><strong>Calculation Mode:</strong> {calculationMode}</p>";

                        // Get packing type fields for this packing master
                        var packingFields = GetPackingTypeFieldsForPDF(packingId);
                        
                        // Display packing details
                        html += $@"
            <div class='calculation-section'>
                <h5>Packing Details</h5>
                <table class='table'>
                    <tr><th>Slab Size</th><th>Count</th></tr>";

                        var pckValues = new[] { 
                            calculation.PCK1, calculation.PCK2, calculation.PCK3, calculation.PCK4, 
                            calculation.PCK5, calculation.PCK6, calculation.PCK7, calculation.PCK8, 
                            calculation.PCK9, calculation.PCK10, calculation.PCK11, calculation.PCK12, 
                            calculation.PCK13, calculation.PCK14, calculation.PCK15, calculation.PCK16, 
                            calculation.PCK17 
                        };

                        for (int i = 0; i < pckValues.Length && i < packingFields.Count; i++)
                        {
                            if (pckValues[i] > 0)
                            {
                                html += $@"
                    <tr><td>{packingFields[i]}</td><td class='value'>{pckValues[i]:F3}</td></tr>";
                            }
                        }

                        html += $@"
                    <tr style='background-color: #e9ecef;'><th>Total (Slab):</th><th class='value'>{calculation.TOPCK:F3}</th></tr>
                </table>
            </div>";

                        // Display calculation results based on mode
                        if (calculation.CALCULATIONMODE == 2) // Grade Weight Mode
                        {
                            html += $@"
            <div class='calculation-section'>
                <h5>Grade Weight Calculation</h5>
                <table class='table'>
                    <tr><th>Slab:</th><td class='value'>{calculation.TOPCK:F3}</td></tr>
                    <tr><th>Peeled:</th><td class='value'>{calculation.WASTEWGT:F3}</td></tr>
                    <tr style='background-color: #e9ecef;'><th>Factory Weight:</th><th class='value'>{calculation.FACTORYWGT:F3}</th></tr>
                </table>
            </div>";
                        }
                        else // Packing Mode
                        {
                            html += $@"
            <div class='calculation-section'>
                <h5>Slab Calculation</h5>
                <table class='table'>
                    <tr><th>Total PCK:</th><td class='value'>{calculation.TOPCK:F3}</td></tr>
                    <tr><th>PCK L Value:</th><td class='value'>{calculation.PCKLVALUE:F3}</td></tr>
                    <tr><th>Avg PCK Value:</th><td class='value'>{calculation.AVGPCKVALUE:F3}</td></tr>
                    <tr><th>PNDS Value:</th><td class='value'>{calculation.PNDSVALUE:F3}</td></tr>
                    <tr><th>Total PNDS:</th><td class='value'>{calculation.TOTALPNDS:F3}</td></tr>
                </table>
            </div>

            <div class='calculation-section'>
                <h5>Total Weight Calculation</h5>
                <table class='table'>
                    <tr><th>Yield Percent:</th><td class='value'>{calculation.YELDPERCENT:F3}%</td></tr>
                    <tr><th>Total Yield Counts:</th><td class='value'>{calculation.TOTALYELDCOUNTS:F3}</td></tr>
                    <tr><th>KG Weight:</th><td class='value'>{calculation.KGWGT:F3}</td></tr>
                    <tr><th>PCK KG Weight:</th><td class='value'>{calculation.PCKKGWGT:F3}</td></tr>
                    <tr><th>Waste Weight:</th><td class='value'>{calculation.WASTEWGT:F3}</td></tr>
                    <tr><th>Waste P Weight:</th><td class='value'>{calculation.WASTEPWGT:F3}</td></tr>
                    <tr style='background-color: #e9ecef;'><th>Factory Weight:</th><th class='value'>{calculation.FACTORYWGT:F3}</th></tr>
                </table>
            </div>";
                        }

                        html += @"
        </div>"; // End packing-section
                    }
                }
                else
                {
                    html += @"
        <div class='no-calculations'>No calculations available for this product.</div>";
                }

                html += @"
    </div>"; // End section
            }

            html += @"
</body>
</html>";

            return html;
        }

        private List<string> GetPackingTypeFieldsForPDF(int packingId)
        {
            try
            {
                var packingTypes = db.PackingTypeMasters
                    .Where(pt => pt.PACKMID == packingId && pt.DISPSTATUS == 0)
                    .OrderBy(pt => pt.PACKTMCODE)
                    .Select(pt => pt.PACKTMDESC)
                    .ToList();

                return packingTypes.Any() ? packingTypes : new List<string> 
                { 
                    "PCK1", "PCK2", "PCK3", "PCK4", "PCK5", "PCK6", "PCK7", "PCK8", "PCK9", 
                    "PCK10", "PCK11", "PCK12", "PCK13", "PCK14", "PCK15", "PCK16", "PCK17" 
                };
            }
            catch
            {
                return new List<string> 
                { 
                    "PCK1", "PCK2", "PCK3", "PCK4", "PCK5", "PCK6", "PCK7", "PCK8", "PCK9", 
                    "PCK10", "PCK11", "PCK12", "PCK13", "PCK14", "PCK15", "PCK16", "PCK17" 
                };
            }
        }

        // Generate Transaction PDF for Index page Print button
        public ActionResult GenerateTransactionPDF(int id)
        {
            try
            {
                var htmlContent = GenerateTransactionPDFContent(id);
                
                Response.ContentType = "text/html";
                Response.AddHeader("Content-Disposition", $"inline; filename=RawMaterialIntake_{id}.html");
                
                return Content(htmlContent);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[GenerateTransactionPDF] Error: {ex.Message}");
                return Content($"<html><body><h3>Error generating PDF: {ex.Message}</h3></body></html>");
            }
        }

        private string GenerateTransactionPDFContent(int tranmid)
        {
            // Get transaction master data
            var transaction = db.TransactionMasters.FirstOrDefault(t => t.TRANMID == tranmid);
            if (transaction == null)
            {
                return "<html><body><h3>Transaction not found</h3></body></html>";
            }

            // Get transaction details with product information using Entity Framework
            var details = (from td in db.TransactionDetails
                          join m in db.MaterialMasters on td.MTRLID equals m.MTRLID
                          join mg in db.MaterialGroupMasters on td.MTRLGID equals mg.MTRLGID
                          where td.TRANMID == tranmid
                          select new
                          {
                              td.TRANDID,
                              td.TRANMID,
                              td.MTRLNBOX,
                              td.MTRLCOUNTS,
                              ProductType = mg.MTRLGDESC,
                              ProductName = m.MTRLDESC
                          }).OrderBy(x => x.TRANDID).ToList();

            var html = $@"
<!DOCTYPE html>
<html>
<head>
    <meta charset='utf-8'>
    <title>Raw Material Intake - {transaction.TRANMID}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f8f9fa; }}
        .container {{ max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; margin-bottom: 30px; padding-bottom: 20px; border-bottom: 3px solid #007bff; }}
        .company-name {{ font-size: 28px; font-weight: bold; color: #007bff; margin-bottom: 5px; }}
        .document-title {{ font-size: 20px; color: #6c757d; margin-bottom: 10px; }}
        .transaction-info {{ background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%); padding: 20px; border-radius: 8px; margin-bottom: 25px; }}
        .info-row {{ display: flex; justify-content: space-between; margin-bottom: 10px; }}
        .info-label {{ font-weight: bold; color: #1976d2; }}
        .info-value {{ color: #424242; }}
        .section-title {{ font-size: 18px; font-weight: bold; color: #007bff; margin: 25px 0 15px 0; padding-bottom: 8px; border-bottom: 2px solid #e9ecef; }}
        .table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
        .table th, .table td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
        .table th {{ background: linear-gradient(135deg, #007bff, #0056b3); color: white; font-weight: 600; }}
        .table tbody tr:nth-child(even) {{ background-color: #f8f9fa; }}
        .table tbody tr:hover {{ background-color: #e3f2fd; }}
        .value {{ text-align: right; font-weight: 600; }}
        .total-row {{ background: linear-gradient(135deg, #28a745, #20c997) !important; color: white; font-weight: bold; }}
        .no-data {{ text-align: center; color: #6c757d; font-style: italic; padding: 20px; }}
        @media print {{ 
            body {{ background: white; }} 
            .container {{ box-shadow: none; }} 
            @page {{ margin: 1in; }}
        }}
    </style>
    <script>
        window.onload = function() {{
            window.print();
        }};
    </script>
</head>
<body>
    <div class='container'>
        <div class='header'>
            <div class='company-name'>MARINEX</div>
            <div class='document-title'>Raw Material Intake Report</div>
            <div style='color: #6c757d; font-size: 14px;'>Transaction ID: {transaction.TRANMID}</div>
        </div>

        <div class='transaction-info'>
            <div class='info-row'>
                <span class='info-label'>Date:</span>
                <span class='info-value'>{transaction.TRANDATE:dd/MM/yyyy}</span>
            </div>
            <div class='info-row'>
                <span class='info-label'>Supplier Name:</span>
                <span class='info-value'>{transaction.CATENAME}</span>
            </div>
            <div class='info-row'>
                <span class='info-label'>Supplier Code:</span>
                <span class='info-value'>{transaction.CATECODE}</span>
            </div>
            <div class='info-row'>
                <span class='info-label'>Vehicle No:</span>
                <span class='info-value'>{transaction.VECHNO}</span>
            </div>
            <div class='info-row'>
                <span class='info-label'>Client Weight (KG):</span>
                <span class='info-value'>{transaction.CLIENTWGHT:F2} KG</span>
            </div>
        </div>";

            if (details.Any())
            {
                html += @"
        <div class='section-title'>Product Details</div>
        <table class='table'>
            <thead>
                <tr>
                    <th>S.No</th>
                    <th>Product Type</th>
                    <th>Product Name</th>
                    <th>No of Boxes</th>
                    <th>Counts per KG</th>
                </tr>
            </thead>
            <tbody>";

                int serialNo = 1;
                int totalBoxes = 0;

                foreach (var detail in details)
                {
                    totalBoxes += detail.MTRLNBOX;

                    html += $@"
                <tr>
                    <td>{serialNo}</td>
                    <td>{detail.ProductType}</td>
                    <td>{detail.ProductName}</td>
                    <td class='value'>{detail.MTRLNBOX}</td>
                    <td class='value'>{detail.MTRLCOUNTS}</td>
                </tr>";
                    serialNo++;
                }

                html += $@"
                <tr class='total-row'>
                    <td colspan='3'><strong>Total No.of Boxes</strong></td>
                    <td colspan='2' class='value' style='text-align: center;'><strong>{totalBoxes}</strong></td>
                </tr>
            </tbody>
        </table>";
            }
            else
            {
                html += @"
        <div class='section-title'>Product Details</div>
        <div class='no-data'>No product details available for this transaction.</div>";
            }

            html += $@"
        <div style='margin-top: 40px; text-align: center; color: #6c757d; font-size: 12px;'>
            Generated on {DateTime.Now:dd/MM/yyyy HH:mm} | MARINEX ERP System
        </div>
    </div>
</body>
</html>";

            return html;
        }

        // Get total factory weight for a specific transaction detail (product row)
        [HttpGet]
        public ActionResult GetFactoryWeight(int trandid)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"[GetFactoryWeight] Looking for TRANDID: {trandid}");
                
                var calculations = db.TransactionProductCalculations
                    .Where(calc => calc.TRANDID == trandid && calc.DISPSTATUS == 0)
                    .ToList();
                
                System.Diagnostics.Debug.WriteLine($"[GetFactoryWeight] Found {calculations.Count} calculations for TRANDID {trandid}");
                
                var totalFactoryWeight = calculations.Sum(calc => calc.FACTORYWGT);
                
                System.Diagnostics.Debug.WriteLine($"[GetFactoryWeight] Total factory weight: {totalFactoryWeight}");
                
                foreach (var calc in calculations)
                {
                    System.Diagnostics.Debug.WriteLine($"[GetFactoryWeight] TRANPID: {calc.TRANPID}, PACKMID: {calc.PACKMID}, FACTORYWGT: {calc.FACTORYWGT}");
                }

                return Json(new { success = true, factoryWeight = totalFactoryWeight }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"[GetFactoryWeight] Error: {ex.Message}");
                return Json(new { success = false, error = ex.Message }, JsonRequestBehavior.AllowGet);
            }
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
