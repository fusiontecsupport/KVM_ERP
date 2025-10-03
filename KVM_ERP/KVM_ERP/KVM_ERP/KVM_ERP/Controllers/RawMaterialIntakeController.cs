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
