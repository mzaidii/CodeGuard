using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using System.Net;
using System.Xml;

namespace VulnerableApp.Controllers
{
    public class VulnController : Controller
    {
        // Hardcoded Secrets
        private const string DB_PASSWORD = "SuperSecret123!";
        private const string API_KEY = "sk-prod-abc123xyz789";
        private const string JWT_SECRET = "my-jwt-secret-key";
        private string connectionString = "Server=localhost;Database=mydb;User=sa;Password=Admin123!";

        // SQL Injection
        [HttpGet]
        public ActionResult GetUser(string userId)
        {
            string query = "SELECT * FROM Users WHERE UserId = '" + userId + "'";
            
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                SqlCommand cmd = new SqlCommand(query, conn);
                conn.Open();
                SqlDataReader reader = cmd.ExecuteReader();
                return Json(reader, JsonRequestBehavior.AllowGet);
            }
        }

        // SQL Injection - Login
        [HttpPost]
        public ActionResult Login(string username, string password)
        {
            string query = $"SELECT * FROM Users WHERE Username='{username}' AND Password='{password}'";
            
            using (SqlConnection conn = new SqlConnection(connectionString))
            {
                SqlCommand cmd = new SqlCommand(query, conn);
                conn.Open();
                var result = cmd.ExecuteScalar();
                return result != null ? Json(new { success = true }) : Json(new { success = false });
            }
        }

        // XSS - Reflected
        [HttpGet]
        public ActionResult Search(string query)
        {
            ViewBag.SearchQuery = query;
            return Content("<html><body>You searched for: " + query + "</body></html>", "text/html");
        }

        // XSS - Html.Raw
        [HttpGet]
        public ActionResult DisplayMessage(string message)
        {
            return Content($"<div>{Html.Raw(message)}</div>");
        }
        
        


        // Command Injection
        [HttpGet]
        public ActionResult Ping(string host)
        {
            Process process = new Process();
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c ping " + host;
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.Start();
            
            string output = process.StandardOutput.ReadToEnd();
            return Content(output);
        }

        // Command Injection - Another example
        [HttpGet]
        public ActionResult RunCommand(string cmd)
        {
            Process.Start("cmd.exe", "/c " + cmd);
            return Content("Command executed");
        }

        // Path Traversal
        [HttpGet]
        public ActionResult DownloadFile(string filename)
        {
            string filePath = Path.Combine("C:\\uploads\\", filename);
            byte[] fileBytes = System.IO.File.ReadAllBytes(filePath);
            return File(fileBytes, "application/octet-stream", filename);
        }

        // Path Traversal - StreamReader
        [HttpGet]
        public ActionResult ReadFile(string filename)
        {
            StreamReader reader = new StreamReader("C:\\data\\" + filename);
            string content = reader.ReadToEnd();
            return Content(content);
        }

        // Insecure Deserialization - BinaryFormatter
        [HttpPost]
        public ActionResult DeserializeData(string data)
        {
            byte[] bytes = Convert.FromBase64String(data);
            BinaryFormatter formatter = new BinaryFormatter();
            
            using (MemoryStream stream = new MemoryStream(bytes))
            {
                object obj = formatter.Deserialize(stream);
                return Json(obj);
            }
        }

        // XXE Vulnerability
        [HttpPost]
        public ActionResult ParseXml(string xmlData)
        {
            XmlDocument doc = new XmlDocument();
            doc.XmlResolver = new XmlUrlResolver();
            doc.LoadXml(xmlData);
            return Content(doc.InnerText);
        }

        // Weak Cryptography - MD5
        public string HashPassword(string password)
        {
            using (MD5 md5 = MD5.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(password);
                byte[] hashBytes = md5.ComputeHash(inputBytes);
                return Convert.ToBase64String(hashBytes);
            }
        }

        // Weak Cryptography - SHA1
        public string HashData(string data)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] inputBytes = Encoding.UTF8.GetBytes(data);
                byte[] hashBytes = sha1.ComputeHash(inputBytes);
                return BitConverter.ToString(hashBytes);
            }
        }

        // SSRF
        [HttpGet]
        public ActionResult FetchUrl(string url)
        {
            WebClient client = new WebClient();
            string content = client.DownloadString(url);
            return Content(content);
        }

        // Open Redirect
        [HttpGet]
        public ActionResult Redirect(string url)
        {
            return Redirect(url);
        }

        // Insecure Random
        public string GenerateToken()
        {
            Random random = new Random();
            return random.Next().ToString();
        }

        // Missing Authentication - Sensitive endpoint without [Authorize]
        [HttpGet]
        public ActionResult GetAllUsers()
        {
            string query = "SELECT * FROM Users";
            // Returns all users without authentication check
            return Json(new { users = "all_users_data" }, JsonRequestBehavior.AllowGet);
        }

        // CSRF - Missing ValidateAntiForgeryToken
        [HttpPost]
        public ActionResult ChangePassword(string newPassword)
        {
            // Missing [ValidateAntiForgeryToken]
            // Password change without CSRF protection
            return Json(new { success = true });
        }

        // Debug mode / Information disclosure
        [HttpGet]
        public ActionResult Debug()
        {
            return Content(Environment.StackTrace);
        }
    }
}