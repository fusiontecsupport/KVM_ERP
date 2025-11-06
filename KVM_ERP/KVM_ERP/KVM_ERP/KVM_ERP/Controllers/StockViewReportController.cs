using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Mvc;
using KVM_ERP.Models;
using ClosedXML.Excel;
using System.IO;

namespace KVM_ERP.Controllers
{
    [SessionExpire]
    public class StockViewReportController : Controller
    {
        private ApplicationDbContext db = new ApplicationDbContext();

        // GET: StockViewReport
        [Authorize(Roles = "StockViewReportIndex")]
        public ActionResult Index()
        {
            ViewBag.Title = "Stock View Report";
            return View();
        }

        [HttpPost]
        public JsonResult GetStockData(string fromDate, string toDate, string tab = "HL")
        {
            try
            {
                DateTime from = DateTime.Parse(fromDate);
                DateTime to = DateTime.Parse(toDate);

                System.Diagnostics.Debug.WriteLine($"GetStockData called - From: {from:yyyy-MM-dd}, To: {to:yyyy-MM-dd}, Tab: {tab}");

                // Get stock data from TRANSACTION_PRODUCT_CALCULATION table
                var stockData = GetStockViewReportData(from, to, tab);

                return Json(new { success = true, data = stockData }, JsonRequestBehavior.AllowGet);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in GetStockData: {ex.Message}");
                return Json(new { success = false, message = ex.Message }, JsonRequestBehavior.AllowGet);
            }
        }

        [HttpPost]
        public ActionResult ExportToExcel(string fromDate, string toDate, string tab = "HL")
        {
            try
            {
                DateTime from = DateTime.Parse(fromDate);
                DateTime to = DateTime.Parse(toDate);

                var stockData = GetStockViewReportData(from, to, tab);

                using (var workbook = new XLWorkbook())
                {
                    var worksheet = workbook.Worksheets.Add($"Stock View - {tab}");

                    // Add header
                    worksheet.Cell(1, 1).Value = "1/30, Padur Village, Kelambakkam, Kanchipuram Dist - 603 103.";
                    worksheet.Cell(1, 1).Style.Font.Bold = true;
                    worksheet.Range(1, 1, 1, 18).Merge();

                    worksheet.Cell(2, 1).Value = $"STOCK AS ON {to:dd/MM/yyyy}";
                    worksheet.Cell(2, 1).Style.Font.Bold = true;
                    worksheet.Range(2, 1, 2, 18).Merge();

                    // Add column headers
                    int row = 4;
                    worksheet.Cell(row, 1).Value = "PARTICULARS";
                    worksheet.Cell(row, 2).Value = "U/S";
                    worksheet.Cell(row, 3).Value = "6-8";
                    worksheet.Cell(row, 4).Value = "8/12";
                    worksheet.Cell(row, 5).Value = "13/15";
                    worksheet.Cell(row, 6).Value = "16/20";
                    worksheet.Cell(row, 7).Value = "21/25";
                    worksheet.Cell(row, 8).Value = "26/30";
                    worksheet.Cell(row, 9).Value = "31/35";
                    worksheet.Cell(row, 10).Value = "36/40";
                    worksheet.Cell(row, 11).Value = "41/50";
                    worksheet.Cell(row, 12).Value = "51/60";
                    worksheet.Cell(row, 13).Value = "61/70";
                    worksheet.Cell(row, 14).Value = "71/90";
                    worksheet.Cell(row, 15).Value = "91/110";
                    worksheet.Cell(row, 16).Value = "TOTAL NO. OF SLABS";

                    // Style headers
                    worksheet.Range(row, 1, row, 16).Style.Font.Bold = true;
                    worksheet.Range(row, 1, row, 16).Style.Fill.BackgroundColor = XLColor.LightGray;
                    worksheet.Range(row, 1, row, 16).Style.Border.OutsideBorder = XLBorderStyleValues.Thin;

                    // Add data rows
                    row++;
                    foreach (var item in stockData)
                    {
                        worksheet.Cell(row, 1).Value = item.ProductName;
                        worksheet.Cell(row, 2).Value = item.US;
                        worksheet.Cell(row, 3).Value = item.Size6_8;
                        worksheet.Cell(row, 4).Value = item.Size8_12;
                        worksheet.Cell(row, 5).Value = item.Size13_15;
                        worksheet.Cell(row, 6).Value = item.Size16_20;
                        worksheet.Cell(row, 7).Value = item.Size21_25;
                        worksheet.Cell(row, 8).Value = item.Size26_30;
                        worksheet.Cell(row, 9).Value = item.Size31_35;
                        worksheet.Cell(row, 10).Value = item.Size36_40;
                        worksheet.Cell(row, 11).Value = item.Size41_50;
                        worksheet.Cell(row, 12).Value = item.Size51_60;
                        worksheet.Cell(row, 13).Value = item.Size61_70;
                        worksheet.Cell(row, 14).Value = item.Size71_90;
                        worksheet.Cell(row, 15).Value = item.Size91_110;
                        worksheet.Cell(row, 16).Value = item.TotalSlabs;

                        // Add sub-rows (OPENING STOCK, PRODUCTION, TOTAL, RATE, AMOUNT)
                        // This is a simplified version - you'll need to expand this based on your data structure
                        row++;
                    }

                    // Auto-fit columns
                    worksheet.Columns().AdjustToContents();

                    using (var stream = new MemoryStream())
                    {
                        workbook.SaveAs(stream);
                        var content = stream.ToArray();
                        return File(content, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            $"StockViewReport_{tab}_{DateTime.Now:yyyyMMdd}.xlsx");
                    }
                }
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = "Error exporting to Excel: " + ex.Message;
                return RedirectToAction("Index");
            }
        }

        private List<StockViewReportData> GetStockViewReportData(DateTime fromDate, DateTime toDate, string tab)
        {
            try
            {
                System.Diagnostics.Debug.WriteLine($"GetStockViewReportData - From: {fromDate:yyyy-MM-dd}, To: {toDate:yyyy-MM-dd}, Tab: {tab}");

                var stockData = new List<StockViewReportData>();

                // Get all calculations within the date range
                var allCalcs = (from tpc in db.TransactionProductCalculations
                               join td in db.TransactionDetails on tpc.TRANDID equals td.TRANDID
                               join m in db.MaterialMasters on td.MTRLID equals m.MTRLID
                               join tm in db.TransactionMasters on td.TRANMID equals tm.TRANMID
                               where (tpc.DISPSTATUS == 0 || tpc.DISPSTATUS == null)
                                     && (m.DISPSTATUS == 0 || m.DISPSTATUS == null)
                                     && (tm.DISPSTATUS == 0 || tm.DISPSTATUS == null)
                                     && tm.TRANDATE >= fromDate
                                     && tm.TRANDATE <= toDate
                               select new {
                                   ProductId = m.MTRLID,
                                   ProductName = m.MTRLDESC,
                                   PCK1 = tpc.PCK1,
                                   PCK2 = tpc.PCK2,
                                   PCK3 = tpc.PCK3,
                                   PCK4 = tpc.PCK4,
                                   PCK5 = tpc.PCK5,
                                   PCK6 = tpc.PCK6,
                                   PCK7 = tpc.PCK7,
                                   PCK8 = tpc.PCK8,
                                   PCK9 = tpc.PCK9,
                                   PCK10 = tpc.PCK10,
                                   PCK11 = tpc.PCK11,
                                   PCK12 = tpc.PCK12,
                                   PCK13 = tpc.PCK13,
                                   PCK14 = tpc.PCK14,
                                   PCK15 = tpc.PCK15,
                                   PCK16 = tpc.PCK16,
                                   PCK17 = tpc.PCK17
                               }).ToList();

                System.Diagnostics.Debug.WriteLine($"Found {allCalcs.Count} calculation records");

                if (allCalcs.Any())
                {
                    // Group by product and sum PCK values
                    var grouped = allCalcs.GroupBy(x => new { x.ProductId, x.ProductName })
                                         .Select(g => new StockViewReportData
                                         {
                                             ProductName = g.Key.ProductName,
                                             US = g.Sum(x => x.PCK1),
                                             Size6_8 = g.Sum(x => x.PCK2),
                                             Size8_12 = g.Sum(x => x.PCK3),
                                             Size13_15 = g.Sum(x => x.PCK4),
                                             Size16_20 = g.Sum(x => x.PCK5),
                                             Size21_25 = g.Sum(x => x.PCK6),
                                             Size26_30 = g.Sum(x => x.PCK7),
                                             Size31_35 = g.Sum(x => x.PCK8),
                                             Size36_40 = g.Sum(x => x.PCK9),
                                             Size41_50 = g.Sum(x => x.PCK10),
                                             Size51_60 = g.Sum(x => x.PCK11),
                                             Size61_70 = g.Sum(x => x.PCK12),
                                             Size71_90 = g.Sum(x => x.PCK13),
                                             Size91_110 = g.Sum(x => x.PCK14),
                                             TotalSlabs = (int)(g.Sum(x => x.PCK1 + x.PCK2 + x.PCK3 + x.PCK4 + x.PCK5 + 
                                                                           x.PCK6 + x.PCK7 + x.PCK8 + x.PCK9 + x.PCK10 + 
                                                                           x.PCK11 + x.PCK12 + x.PCK13 + x.PCK14 + x.PCK15 + 
                                                                           x.PCK16 + x.PCK17))
                                         })
                                         .OrderBy(x => x.ProductName)
                                         .ToList();

                    stockData = grouped;
                    System.Diagnostics.Debug.WriteLine($"Grouped into {stockData.Count} products");
                }

                return stockData;
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Error in GetStockViewReportData: {ex.Message}");
                return new List<StockViewReportData>();
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

    // Model for Stock View Report Data
    public class StockViewReportData
    {
        public string ProductName { get; set; }
        public decimal US { get; set; }
        public decimal Size6_8 { get; set; }
        public decimal Size8_12 { get; set; }
        public decimal Size13_15 { get; set; }
        public decimal Size16_20 { get; set; }
        public decimal Size21_25 { get; set; }
        public decimal Size26_30 { get; set; }
        public decimal Size31_35 { get; set; }
        public decimal Size36_40 { get; set; }
        public decimal Size41_50 { get; set; }
        public decimal Size51_60 { get; set; }
        public decimal Size61_70 { get; set; }
        public decimal Size71_90 { get; set; }
        public decimal Size91_110 { get; set; }
        public decimal TotalSlabs { get; set; }
    }
}
