package main

import (
	"crypto/md5"
	"crypto/sha1"
	"database/sql"
	"encoding/gob"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

// Hardcoded Secrets
const (
	DB_PASSWORD  = "SuperSecret123!"
	API_KEY      = "sk-1234567890abcdef"
	JWT_SECRET   = "my_jwt_secret_key"
	PRIVATE_KEY  = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA..."
)

var (
	password     = "admin123"
	secretToken  = "token_abc123"
	databaseUrl  = "mysql://root:password123@localhost/mydb"
)

type User struct {
	ID       int
	Username string
	Email    string
	Password string
}

type VulnController struct {
	db *sql.DB
}

func NewVulnController() *VulnController {
	// Hardcoded connection string
	db, _ := sql.Open("mysql", "root:password123@tcp(localhost:3306)/mydb")
	return &VulnController{db: db}
}

// SQL Injection - String concatenation
func (c *VulnController) GetUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	query := "SELECT * FROM users WHERE id = " + id
	rows, _ := c.db.Query(query)
	defer rows.Close()
	// Process rows...
}

// SQL Injection - fmt.Sprintf
func (c *VulnController) SearchUsers(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	query := fmt.Sprintf("SELECT * FROM users WHERE name LIKE '%%%s%%'", name)
	rows, _ := c.db.Query(query)
	defer rows.Close()
}

// SQL Injection - Direct concatenation in Exec
func (c *VulnController) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	c.db.Exec("DELETE FROM users WHERE id = " + id)
}

// Command Injection - exec.Command with user input
func (c *VulnController) Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	cmd := exec.Command("ping", "-c", "4", host)
	output, _ := cmd.Output()
	w.Write(output)
}

// Command Injection - Shell execution
func (c *VulnController) RunCommand(w http.ResponseWriter, r *http.Request) {
	userCmd := r.URL.Query().Get("cmd")
	cmd := exec.Command("sh", "-c", userCmd)
	output, _ := cmd.Output()
	w.Write(output)
}

// Command Injection - os/exec with concatenation
func (c *VulnController) ExecuteScript(w http.ResponseWriter, r *http.Request) {
	script := r.URL.Query().Get("script")
	cmd := exec.Command("bash", "-c", "echo "+script)
	cmd.Run()
}

// Path Traversal - Reading file with user input
func (c *VulnController) ReadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")
	content, _ := ioutil.ReadFile("/var/www/files/" + filename)
	w.Write(content)
}

// Path Traversal - Using filepath without validation
func (c *VulnController) ServeFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	fullPath := filepath.Join("/var/www/public", path)
	http.ServeFile(w, r, fullPath)
}

// Path Traversal - os.Open with user input
func (c *VulnController) DownloadFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	file, _ := os.Open("/uploads/" + filename)
	defer file.Close()
	io.Copy(w, file)
}

// XSS - Direct output without encoding
func (c *VulnController) DisplayMessage(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	fmt.Fprintf(w, "<html><body><h1>%s</h1></body></html>", message)
}

// XSS - Writing user input directly
func (c *VulnController) WelcomeUser(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	w.Write([]byte("<div>Welcome, " + username + "!</div>"))
}

// SSRF - Fetching user-provided URL
func (c *VulnController) FetchURL(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	resp, _ := http.Get(url)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	w.Write(body)
}

// SSRF - Using http.NewRequest with user input
func (c *VulnController) ProxyRequest(w http.ResponseWriter, r *http.Request) {
	targetURL := r.URL.Query().Get("target")
	req, _ := http.NewRequest("GET", targetURL, nil)
	client := &http.Client{}
	resp, _ := client.Do(req)
	defer resp.Body.Close()
	io.Copy(w, resp.Body)
}

// Open Redirect - Unvalidated redirect
func (c *VulnController) Redirect(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	http.Redirect(w, r, url, http.StatusFound)
}

// Open Redirect - Login redirect without validation
func (c *VulnController) LoginRedirect(w http.ResponseWriter, r *http.Request) {
	redirectURL := r.URL.Query().Get("redirect")
	// After login, redirect to user-provided URL
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// Insecure Deserialization - Using gob decoder
func (c *VulnController) LoadSession(w http.ResponseWriter, r *http.Request) {
	decoder := gob.NewDecoder(r.Body)
	var session map[string]interface{}
	decoder.Decode(&session)
	// Use session data...
}

// XXE - XML parsing without disabling entities
func (c *VulnController) ParseXML(w http.ResponseWriter, r *http.Request) {
	body, _ := ioutil.ReadAll(r.Body)
	var data interface{}
	xml.Unmarshal(body, &data)
	fmt.Fprintf(w, "Parsed: %v", data)
}

// Weak Cryptography - MD5 for hashing
func (c *VulnController) HashPassword(password string) string {
	hash := md5.New()
	hash.Write([]byte(password))
	return hex.EncodeToString(hash.Sum(nil))
}

// Weak Cryptography - SHA1 for sensitive data
func (c *VulnController) HashData(data string) string {
	hash := sha1.New()
	hash.Write([]byte(data))
	return hex.EncodeToString(hash.Sum(nil))
}

// Insecure Random - Using math/rand for tokens
func (c *VulnController) GenerateToken() string {
	rand.Seed(time.Now().UnixNano())
	token := rand.Int63()
	return fmt.Sprintf("%d", token)
}

// Insecure Random - Using rand for session ID
func (c *VulnController) GenerateSessionID() string {
	return fmt.Sprintf("%d%d%d", rand.Int(), rand.Int(), rand.Int())
}

// Missing Authentication - No auth middleware
func (c *VulnController) AdminPanel(w http.ResponseWriter, r *http.Request) {
	// No authentication check
	w.Write([]byte("Welcome to Admin Panel!"))
}

// Missing Authentication - Sensitive operation without auth
func (c *VulnController) DeleteAllUsers(w http.ResponseWriter, r *http.Request) {
	// No authentication
	c.db.Exec("DELETE FROM users")
	w.Write([]byte("All users deleted"))
}

// Information Disclosure - Exposing stack trace
func (c *VulnController) DangerousOperation(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			// Exposing internal error details
			fmt.Fprintf(w, "Error: %v", err)
		}
	}()
	
	// Some dangerous operation
	panic("Something went wrong!")
}

func main() {
	controller := NewVulnController()
	
	// Routes without authentication
	http.HandleFunc("/user", controller.GetUser)
	http.HandleFunc("/search", controller.SearchUsers)
	http.HandleFunc("/delete", controller.DeleteUser)
	http.HandleFunc("/ping", controller.Ping)
	http.HandleFunc("/run", controller.RunCommand)
	http.HandleFunc("/file", controller.ReadFile)
	http.HandleFunc("/message", controller.DisplayMessage)
	http.HandleFunc("/fetch", controller.FetchURL)
	http.HandleFunc("/redirect", controller.Redirect)
	http.HandleFunc("/admin", controller.AdminPanel)
	
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
