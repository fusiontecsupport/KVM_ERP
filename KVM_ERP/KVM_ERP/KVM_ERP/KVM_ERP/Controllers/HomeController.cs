using ClubMembership.Data;
using KVM_ERP.Filters;
using KVM_ERP.Models;
using DocumentFormat.OpenXml.Office2010.Excel;
using DocumentFormat.OpenXml.Office2016.Drawing.ChartDrawing;
using log4net;
using Microsoft.AspNet.Identity;
using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.SqlClient;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace KVM_ERP.Controllers
{
    // Model for Event Interest Statistics
    public class EventInterestStat
    {
        public string EventId { get; set; }
        public string EventName { get; set; }
        public DateTime EventDate { get; set; }
        public string EventLocation { get; set; }
        public int InterestedCount { get; set; }
        public int NotInterestedCount { get; set; }
        public int TotalResponses { get; set; }
    }

    // Simple DTOs for Notifications sidebar
    public class SimpleMember
    {
        public int MemberID { get; set; }
        public string Member_Name { get; set; }
        public string Member_Photo_Path { get; set; }
    }

    public class SpouseBirthday
    {
        public int MemberID { get; set; }
        public string Member_Name { get; set; }
        public string Spouse_Name { get; set; }
    }

    public class AnniversaryItem
    {
        public int MemberID { get; set; }
        public string Member_Name { get; set; }
        public string Spouse_Name { get; set; }
        public DateTime Date_Of_Marriage { get; set; }
    }

    // [AuthActionFilter]
    public class HomeController : Controller
    {
        private readonly ApplicationDbContext _db;
        //private static readonly ILog log = LogManager.GetLogger(typeof(MembersController));

        public HomeController()
        {
            _db = new ApplicationDbContext();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult SendWish(int memberId, string type, string recipient, string note)
        {
            // Module removed
            return new HttpStatusCodeResult(204);
        }

        private string BuildWishEmailHtml(string title, string message, string senderFirstName, string recipientName, string note)
        {
            // Lightweight, email-client friendly HTML with inline styles
            return $@"<!DOCTYPE html>
<html>
  <head>
    <meta charset='utf-8' />
    <meta name='viewport' content='width=device-width, initial-scale=1' />
    <title>{System.Net.WebUtility.HtmlEncode(title)}</title>
  </head>
  <body style='margin:0;padding:0;background:#f6f7fb;'>
    <table role='presentation' cellpadding='0' cellspacing='0' width='100%' style='background:#f6f7fb;padding:24px 12px;'>
      <tr>
        <td align='center'>
          <table role='presentation' cellpadding='0' cellspacing='0' width='100%' style='max-width:560px;background:#ffffff;border-radius:12px;box-shadow:0 4px 16px rgba(0,0,0,0.06);overflow:hidden;'>
            <tr>
              <td style='background:#0d6efd;height:6px;'></td>
            </tr>
            <tr>
              <td style='padding:24px 24px 8px 24px;font-family:Segoe UI,Roboto,Arial,sans-serif;'>
                <h2 style='margin:0 0 10px 0;color:#0d6efd;font-size:22px;font-weight:700;'>{System.Net.WebUtility.HtmlEncode(title)}</h2>
                <p style='margin:0;color:#6c757d;font-size:14px;'>A warm message from a fellow club member</p>
              </td>
            </tr>
            <tr>
              <td style='padding:8px 24px 24px 24px;font-family:Segoe UI,Roboto,Arial,sans-serif;color:#212529;'>
                <p style='font-size:16px;line-height:1.6;margin:0 0 12px 0;'>Dear {System.Net.WebUtility.HtmlEncode(recipientName)},</p>
                <p style='font-size:16px;line-height:1.6;margin:0 0 12px 0;'>{System.Net.WebUtility.HtmlEncode(message)}</p>
                {(string.IsNullOrWhiteSpace(note) ? "" : ("<div style='background:#f8f9fa;border:1px solid #eef2f4;border-radius:8px;padding:12px 14px;margin:0 0 12px 0;'><div style='color:#6c757d;font-size:12px;margin-bottom:6px;'>Personal message</div><div style='font-size:15px;line-height:1.6;color:#212529;'>" + System.Net.WebUtility.HtmlEncode(note) + "</div></div>"))}
                <p style='font-size:16px;line-height:1.6;margin:0 0 12px 0;'>Best regards,<br/><strong>{System.Net.WebUtility.HtmlEncode(senderFirstName)}</strong></p>
              </td>
            </tr>
            <tr>
              <td style='padding:14px 24px 22px 24px;font-family:Segoe UI,Roboto,Arial,sans-serif;border-top:1px solid #eef2f4;color:#6c757d;font-size:12px;'>
                <div>Sent via Club Membership Portal</div>
              </td>
            </tr>
          </table>
          <div style='color:#adb5bd;font-size:12px;margin-top:10px;font-family:Segoe UI,Roboto,Arial,sans-serif;'>
            &copy; {DateTime.Now:yyyy} Club Membership
          </div>
        </td>
      </tr>
    </table>
  </body>
</html>";
        }

        private bool TrySendEmail(string to, string subject, string body, string senderDisplayName, out string error)
        {
            error = null;
            try
            {
                // Ensure TLS 1.2 for Gmail/modern SMTP
                try { System.Net.ServicePointManager.SecurityProtocol |= System.Net.SecurityProtocolType.Tls12; } catch { }

                // Uses SMTP settings from Web.config <system.net><mailSettings><smtp>
                using (var mail = new System.Net.Mail.MailMessage())
                {
                    mail.To.Add(to);
                    mail.Subject = subject;
                    mail.Body = body;
                    mail.IsBodyHtml = true; // allow basic formatting

                    // Respect Web.config <system.net><mailSettings><smtp from="...">. If not present, use DEFAULT_FROM_EMAIL.
                    if (mail.From == null)
                    {
                        var fallbackFrom = System.Configuration.ConfigurationManager.AppSettings["DEFAULT_FROM_EMAIL"] ?? "support@fusiontec.com";
                        mail.From = new System.Net.Mail.MailAddress(fallbackFrom, string.IsNullOrWhiteSpace(senderDisplayName) ? "Club Membership" : senderDisplayName);
                    }

                    using (var smtp = new System.Net.Mail.SmtpClient())
                    {
                        smtp.Send(mail);
                    }
                }
                return true;
            }
            catch (System.Net.Mail.SmtpException smtpEx)
            {
                var code = smtpEx.StatusCode;
                var msg = smtpEx.Message;
                var inner = smtpEx.InnerException != null ? (": " + smtpEx.InnerException.Message) : string.Empty;
                error = $"SMTP error ({code}): {msg}{inner}";
                return false;
            }
            catch (Exception ex)
            {
                var inner = ex.InnerException != null ? (": " + ex.InnerException.Message) : string.Empty;
                error = ex.Message + inner;
                return false;
            }
        }

        public ActionResult AdminDashboard()
        {
            // Simplified admin dashboard: remove dependencies on membership/payments/content
            if (!User.IsInRole("Admin"))
            {
                return RedirectToAction("Index");
            }
            return View();
        }

        public ActionResult Index()
        {
            // Simplified user dashboard: no membership/content dependencies
            if (User.IsInRole("Admin"))
            {
                return RedirectToAction("AdminDashboard");
            }
            ViewBag.UserName = User.Identity.GetUserName();
            return View("BlankPage");
        }

        [HttpGet]
        public ActionResult RenewalPopup(int memberId)
        {
            return HttpNotFound();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult SubmitRenewal(RenewalSubmitRequest request)
        {
            Response.StatusCode = 404;
            return Json(new { success = false, message = "Not available" });
        }

        [HttpGet]
        public ActionResult Notifications()
        {
            return HttpNotFound();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult AcceptNotification(int eventId)
        {
            return new HttpStatusCodeResult(204);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult DeclineNotification(int eventId)
        {
            return new HttpStatusCodeResult(204);
        }

        [HttpGet]
        public ActionResult UserDashboard()
        {
            return HttpNotFound();
        }
    }
}