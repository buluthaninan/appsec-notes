# SQL Injection

> Status: in progress. Covered so far: basics, WHERE clause, login bypass
> (PortSwigger labs + OWASP Juice Shop), UNION column discovery.

## 1. What is it?
SQL injection is when an attacker slips their own SQL into a query the website
sends to its database. Because the input is pasted into the query as text, the
database runs it as code, giving the attacker data and privileges they were
never meant to have.

## 2. How to find it
- Look for inputs that probably end up in a query: filters, search boxes, IDs,
  login forms, and also cookies and headers.
- First test: add a single quote (`'`) and watch for errors or a broken page.
- Confirm with two conditions: `' OR 1=1--` vs `' OR 1=2--`. Different
  responses mean my input is being evaluated as SQL.
- Work in Burp Repeater and change one thing at a time.

## 3. Variants I practiced
| Type | How I detect it | Lab notes |
|---|---|---|
| WHERE clause, hidden data | More rows appear than the UI should show | `category=Gifts'+OR+1=1--` makes the condition true for every row and comments out `AND released = 1`, so unreleased products show up |
| Login bypass | Logged in without a password | Username `administrator'--` turns the query into `SELECT * FROM users WHERE username = 'administrator'--' AND password = '...'`, so the password check is never evaluated |
| Login bypass on a real-looking app (OWASP Juice Shop) | Logged in as `admin@juice-sh.op` without knowing any username | Email `' OR 1=1--` makes the condition true for every user, so the query returns the whole table. The login code takes the first row, which is the admin account. The response included an auth token that worked on API endpoints that had returned 401 before. To target a specific user instead, I found their email in a product review and used `<email>'--` |
| UNION attack | Data from another table shown in the product list | On the `category` parameter: `' UNION SELECT NULL,NULL,NULL--` found 3 columns (no more internal server error). Then `' UNION SELECT 1,'A',1--` showed which column accepts text. Finally selected the data the lab asked for into that text column |
| UNION: column count | The error disappears at the right count | Added `NULL`s one at a time (`UNION SELECT NULL,NULL,NULL--`). Every wrong count returned 500 Internal Server Error, because both queries in a UNION must return the same number of columns. Here it was 3 |
| UNION: text column | The marker shows up on the page | Replaced one `NULL` at a time with a string. Columns that don't accept text throw an error, so the one that renders the string is where extracted data can be displayed |

## 4. Payloads I used
- `'+OR+1=1--` (the `+` is a URL-encoded space)
- `administrator'--`
- `' OR 1=1--` (Juice Shop email field, sent in a JSON body)
- `<email>'--` (log in as a specific Juice Shop user)
- `' UNION SELECT NULL,NULL,NULL--` (find the column count)
- `' UNION SELECT 1,'A',1--` (find which column accepts text)

## 5. How I'd prevent it as a developer
**Parameterized queries are the fix.** The query structure and the data are
sent separately, so input can never become code.

Vulnerable (C#):
```csharp
var cmd = new SqlCommand(
    "SELECT * FROM users WHERE username = '" + username + "'", conn);
```
Fixed:
```csharp
var cmd = new SqlCommand(
    "SELECT * FROM users WHERE username = @username", conn);
cmd.Parameters.AddWithValue("@username", username);
```

What helps, and what doesn't:
- **ORMs** (Entity Framework, Hibernate, Sequelize) parameterize by default.
  But raw-SQL escape hatches are still dangerous: in EF Core,
  `FromSqlRaw("... WHERE name = '" + name + "'")` is injectable, while
  `FromSqlInterpolated($"... WHERE name = {name}")` is parameterized.
- **Client-side validation** improves UX but is not a security control. In
  these labs I sent whatever I wanted straight from Burp, skipping the browser.
- **Blacklists and escaping** are weak on their own: attackers bypass them
  with encodings, case changes and comments, and they break legitimate input
  like `O'Brien`. Use an allow-list only where parameters can't be used
  (table/column names, `ORDER BY`).
- **Least privilege:** the app's DB user should only have the rights it needs,
  so a successful injection can't drop tables or read everything.

## 6. References
- PortSwigger Web Security Academy: SQL injection
- OWASP SQL Injection Prevention Cheat Sheet
