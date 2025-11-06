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

                    // Add main header - "STOCK AS ON dd/MM/yyyy"
                    int row = 1;
                    worksheet.Cell(row, 1).Value = $"STOCK AS ON {to:dd/MM/yyyy}";
                    worksheet.Cell(row, 1).Style.Font.Bold = true;
                    worksheet.Cell(row, 1).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
                    worksheet.Range(row, 1, row, 17).Merge();
                    
                    // Add column headers - Row 1
                    row++;
                    worksheet.Cell(row, 1).Value = "PARTICULARS";
                    worksheet.Cell(row, 17).Value = "TOTAL NO. OF SLABS";
                    
                    // Merge PARTICULARS cell from row 2 to row 3
                    worksheet.Range(row, 1, row + 1, 1).Merge();
                    // Merge TOTAL NO. OF SLABS cell from row 2 to row 3
                    worksheet.Range(row, 17, row + 1, 17).Merge();
                    
                    // Add column headers - Row 2 (Size columns)
                    row++;
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
                    
                    // Style headers
                    worksheet.Range(2, 1, 3, 17).Style.Font.Bold = true;
                    worksheet.Range(2, 1, 3, 17).Style.Fill.BackgroundColor = XLColor.LightGray;
                    worksheet.Range(2, 1, 3, 17).Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
                    worksheet.Range(2, 1, 3, 17).Style.Border.InsideBorder = XLBorderStyleValues.Thin;
                    worksheet.Range(2, 1, 3, 17).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;

                    // Add data rows
                    row++;
                    int itemNumber = 1;
                    foreach (var item in stockData)
                    {
                        // Product Name Row (merged across all columns except last)
                        worksheet.Cell(row, 1).Value = $"{itemNumber}. {item.ProductName}";
                        worksheet.Range(row, 1, row, 16).Merge();
                        worksheet.Cell(row, 1).Style.Fill.BackgroundColor = XLColor.LightGray;
                        worksheet.Cell(row, 1).Style.Font.Bold = true;
                        worksheet.Cell(row, 17).Value = item.TotalSlabs;
                        worksheet.Cell(row, 17).Style.Fill.BackgroundColor = XLColor.FromArgb(255, 193, 7); // Yellow/Orange
                        worksheet.Cell(row, 17).Style.Font.Bold = true;
                        row++;

                        // OPENING STOCK Row
                        worksheet.Cell(row, 1).Value = "OPENING STOCK";
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
                        worksheet.Cell(row, 17).Value = item.TotalSlabs;
                        worksheet.Range(row, 1, row, 17).Style.Fill.BackgroundColor = XLColor.FromArgb(227, 242, 253); // Light Blue
                        row++;

                        // PRODUCTION Row (all zeros for now)
                        worksheet.Cell(row, 1).Value = "PRODUCTION";
                        for (int col = 2; col <= 17; col++)
                        {
                            worksheet.Cell(row, col).Value = 0;
                        }
                        worksheet.Range(row, 1, row, 17).Style.Fill.BackgroundColor = XLColor.FromArgb(173, 216, 230); // Blue
                        worksheet.Range(row, 1, row, 17).Style.Font.FontColor = XLColor.Blue;
                        row++;

                        // TOTAL Row
                        worksheet.Cell(row, 1).Value = "TOTAL";
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
                        worksheet.Cell(row, 17).Value = item.TotalSlabs;
                        worksheet.Range(row, 1, row, 17).Style.Fill.BackgroundColor = XLColor.FromArgb(212, 237, 218); // Light Green
                        worksheet.Range(row, 1, row, 17).Style.Font.Bold = true;
                        row++;

                        // RATE Row (all zeros)
                        worksheet.Cell(row, 1).Value = "RATE";
                        for (int col = 2; col <= 17; col++)
                        {
                            worksheet.Cell(row, col).Value = 0;
                        }
                        worksheet.Range(row, 1, row, 17).Style.Fill.BackgroundColor = XLColor.FromArgb(248, 215, 218); // Light Red
                        row++;

                        // AMOUNT Row (all zeros)
                        worksheet.Cell(row, 1).Value = "AMOUNT";
                        for (int col = 2; col <= 17; col++)
                        {
                            worksheet.Cell(row, col).Value = 0;
                        }
                        worksheet.Range(row, 1, row, 17).Style.Fill.BackgroundColor = XLColor.FromArgb(209, 236, 241); // Light Cyan
                        row++;

                        itemNumber++;
                    }

                    // Add borders to all data cells
                    worksheet.Range(2, 1, row - 1, 17).Style.Border.OutsideBorder = XLBorderStyleValues.Thin;
                    worksheet.Range(2, 1, row - 1, 17).Style.Border.InsideBorder = XLBorderStyleValues.Thin;
                    
                    // Center align all data cells
                    worksheet.Range(4, 2, row - 1, 17).Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;

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

                // Get all calculations within the date range with additional details
                var allCalcs = (from tpc in db.TransactionProductCalculations
                               join td in db.TransactionDetails on tpc.TRANDID equals td.TRANDID
                               join m in db.MaterialMasters on td.MTRLID equals m.MTRLID
                               join tm in db.TransactionMasters on td.TRANMID equals tm.TRANMID
                               join packing in db.PackingMasters on tpc.PACKMID equals packing.PACKMID into packingLeft
                               from packing in packingLeft.DefaultIfEmpty()
                               join grade in db.GradeMasters on tpc.GRADEID equals grade.GRADEID into gradeLeft
                               from grade in gradeLeft.DefaultIfEmpty()
                               join color in db.ProductionColourMasters on tpc.PCLRID equals color.PCLRID into colorLeft
                               from color in colorLeft.DefaultIfEmpty()
                               join rcvdType in db.ReceivedTypeMasters on tpc.RCVDTID equals rcvdType.RCVDTID into rcvdLeft
                               from rcvdType in rcvdLeft.DefaultIfEmpty()
                               where (tpc.DISPSTATUS == 0 || tpc.DISPSTATUS == null)
                                     && (m.DISPSTATUS == 0 || m.DISPSTATUS == null)
                                     && (tm.DISPSTATUS == 0 || tm.DISPSTATUS == null)
                                     && tm.TRANDATE >= fromDate
                                     && tm.TRANDATE <= toDate
                               select new {
                                   ProductId = m.MTRLID,
                                   ProductName = m.MTRLDESC,
                                   PackingValue = packing != null ? packing.PACKMNOU : 0,
                                   PackingWithGlazing = tpc.PCKLVALUE,
                                   GradeName = grade != null ? grade.GRADEDESC : "",
                                   ColorName = color != null ? color.PCLRDESC : "",
                                   ReceivedTypeName = rcvdType != null ? rcvdType.RCVDTDESC : "",
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
                    // Group by product with detailed breakdown
                    var grouped = allCalcs.GroupBy(x => new { 
                                             x.ProductId, 
                                             x.ProductName, 
                                             x.PackingValue, 
                                             x.PackingWithGlazing, 
                                             x.GradeName, 
                                             x.ColorName, 
                                             x.ReceivedTypeName 
                                         })
                                         .Select(g => new StockViewReportData
                                         {
                                             // Format: "Product Name PackingValue x PackingWithGlazing - Grade - Color - ReceivedType"
                                             // Example: "Head Less 6 x 7 - Grade 1 - Yellow - River"
                                             ProductName = $"{g.Key.ProductName} {g.Key.PackingValue:F0} x {g.Key.PackingWithGlazing:F0}" +
                                                          (!string.IsNullOrEmpty(g.Key.GradeName) ? $" - {g.Key.GradeName}" : "") +
                                                          (!string.IsNullOrEmpty(g.Key.ColorName) ? $" - {g.Key.ColorName}" : "") +
                                                          (!string.IsNullOrEmpty(g.Key.ReceivedTypeName) ? $" - {g.Key.ReceivedTypeName}" : ""),
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
