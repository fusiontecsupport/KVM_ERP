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
        public ActionResult savedata(TransactionMaster tab, int? SupplierId, string detailRowsJson)
        {
            try
            {
                var details = new List<DetailRow>();
                if (!string.IsNullOrWhiteSpace(detailRowsJson))
                {
                    details = JsonConvert.DeserializeObject<List<DetailRow>>(detailRowsJson) ?? new List<DetailRow>();
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
                        existing.DISPSTATUS = tab.DISPSTATUS;
                        existing.LMUSRID = User?.Identity?.Name ?? existing.LMUSRID;
                        existing.PRCSDATE = DateTime.Now; // treat as last modified for simplicity
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
                        TempData["SuccessMessage"] = "Updated successfully";
                        return RedirectToAction("Index");
                    }
                }

                // Insert
                tab.CUSRID = User?.Identity?.Name ?? "System";
                tab.LMUSRID = tab.CUSRID;
                tab.PRCSDATE = DateTime.Now;

                // Insert master and get new TRANMID
                var newId = db.Database.SqlQuery<int>(@"
                    INSERT INTO TRANSACTIONMASTER (TRANDATE, CATENAME, CATECODE, VECHNO, DISPSTATUS, CUSRID, LMUSRID, PRCSDATE)
                    VALUES (@p0, @p1, @p2, @p3, @p4, @p5, @p6, @p7); SELECT CAST(SCOPE_IDENTITY() AS INT);
                ", tab.TRANDATE, tab.CATENAME ?? "", tab.CATECODE ?? "", tab.VECHNO ?? "",
                   tab.DISPSTATUS, tab.CUSRID, tab.LMUSRID, tab.PRCSDATE).FirstOrDefault();

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
        public ActionResult GetAjaxData()
        {
            try
            {
                // Pull minimal fields needed for the Index grid
                var rows = db.Database.SqlQuery<TransactionRow>(
                    @"SELECT tm.TRANMID, tm.TRANDATE, tm.CATENAME, tm.CATECODE, tm.VECHNO, tm.DISPSTATUS,
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
                      ORDER BY tm.TRANDATE DESC, tm.TRANMID DESC"
                ).ToList();

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

        // Get existing product calculation
        public JsonResult GetProductCalculation(int trandid)
        {
            try
            {
                var calculation = db.TransactionProductCalculations.FirstOrDefault(t => t.TRANDID == trandid);
                if (calculation != null)
                {
                    return Json(new { success = true, calculation = calculation }, JsonRequestBehavior.AllowGet);
                }
                return Json(new { success = false, message = "No calculation found" }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        // Save product calculation
        [HttpPost]
        public JsonResult SaveProductCalculation(TransactionProductCalculation model)
        {
            try
            {
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

                // Check if record exists
                var existing = db.TransactionProductCalculations.FirstOrDefault(t => t.TRANDID == model.TRANDID);
                
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
                return Json(new { success = true, message = "Calculation saved successfully" });
            }
            catch (Exception ex)
            {
                return Json(new { success = false, message = ex.Message });
            }
        }

        private void CalculateProductValues(TransactionProductCalculation model)
        {
            // Calculate TOPCK (sum of all PCK fields)
            model.TOPCK = (model.PCK1 ?? 0) + (model.PCK2 ?? 0) + (model.PCK3 ?? 0) + (model.PCK4 ?? 0) + 
                         (model.PCK5 ?? 0) + (model.PCK6 ?? 0) + (model.PCK7 ?? 0) + (model.PCK8 ?? 0) + 
                         (model.PCK9 ?? 0) + (model.PCK10 ?? 0) + (model.PCK11 ?? 0) + (model.PCK12 ?? 0) + 
                         (model.PCK13 ?? 0) + (model.PCK14 ?? 0) + (model.PCK15 ?? 0) + (model.PCK16 ?? 0) + 
                         (model.PCK17 ?? 0);

            if (model.TOPCK > 0)
            {
                // Calculate PCKLVALUE (multiply each PCK with its corresponding value and sum)
                model.PCKLVALUE = CalculatePCKLValue(model);

                // Calculate AVGPCKVALUE
                model.AVGPCKVALUE = model.PCKLVALUE / (decimal)model.TOPCK;

                // Calculate TOTALPNDS
                model.TOTALPNDS = model.AVGPCKVALUE * (model.PNDSVALUE ?? 0);

                // Calculate TOTALYELDCOUNTS
                if (model.YELDPERCENT > 0)
                {
                    model.TOTALYELDCOUNTS = model.TOTALPNDS * (model.YELDPERCENT / 100);
                }

                // Calculate PCKKGWGT
                model.PCKKGWGT = (model.KGWGT ?? 0) * model.TOPCK;

                // Calculate WASTEPWGT
                model.WASTEPWGT = model.PCKKGWGT + (model.WASTEWGT ?? 0);

                // Calculate FACTORYWGT
                if (model.YELDPERCENT > 0)
                {
                    model.FACTORYWGT = model.WASTEPWGT / (model.YELDPERCENT / 100);
                }
            }
        }

        private int CalculatePCKLValue(TransactionProductCalculation model)
        {
            int pcklValue = 0;
            var pckValues = new[] { model.PCK1, model.PCK2, model.PCK3, model.PCK4, model.PCK5, model.PCK6, 
                                   model.PCK7, model.PCK8, model.PCK9, model.PCK10, model.PCK11, model.PCK12, 
                                   model.PCK13, model.PCK14, model.PCK15, model.PCK16, model.PCK17 };

            // Get packing types for this packing master
            var packingTypes = db.PackingTypeMasters
                .Where(pt => pt.PACKMID == model.PACKMID && pt.DISPSTATUS == 0)
                .OrderBy(pt => pt.PACKTMCODE)
                .ToList();

            if (packingTypes.Any())
            {
                for (int i = 0; i < pckValues.Length && i < packingTypes.Count; i++)
                {
                    if (pckValues[i].HasValue && pckValues[i] > 0)
                    {
                        int multiplier = ExtractMultiplierFromDescription(packingTypes[i].PACKTMDESC);
                        pcklValue += pckValues[i].Value * multiplier;
                    }
                }
            }

            return pcklValue;
        }

        private int ExtractMultiplierFromDescription(string description)
        {
            if (string.IsNullOrEmpty(description))
                return 1;

            // Extract number from descriptions like "U - 5", "U - 10", "51-60", "151-200", etc.
            var numbers = System.Text.RegularExpressions.Regex.Matches(description, @"\d+")
                .Cast<System.Text.RegularExpressions.Match>()
                .Select(m => int.Parse(m.Value))
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
