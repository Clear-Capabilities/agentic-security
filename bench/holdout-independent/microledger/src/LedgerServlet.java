// microledger — a tiny invoice-ledger servlet, written purely as scan input
// for the independent external-holdout gate (SARD_80_F1_SCANNER_PRD.md
// adversarial-premortem remediation, P1 item 6). Never compiled or run.
//
// Same discipline as bench/holdout-independent/tinymart (see its README):
// every vulnerable/safe method below was written and classified by reading
// this file, BEFORE the scanner was ever run against it once. See
// scanner/test/benchmark/realworld/expected/microledger.json for the ground
// truth this file's own comments justify line-by-line.

package com.microledger;

import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;
import java.io.IOException;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class LedgerServlet {

    private static final String INVOICES_DIR = "/var/microledger/invoices";
    // A live-shaped-but-obviously-fake AWS access key literal, deliberately
    // using the AKIA test-vector prefix pattern this repo's own catalog
    // already recognizes (same reasoning as tinymart's Stripe test key).
    private static final String BACKUP_AWS_KEY = "AKIAIOSFODNN7EXAMPLE";

    private Connection conn;

    // --- SQL injection: string-concatenated query --------------------------
    public ResultSet findInvoicesByCustomer(HttpServletRequest request) throws SQLException {
        String customer = request.getParameter("customer");
        Statement stmt = conn.createStatement();
        // Vulnerable: customer is attacker-controlled and concatenated
        // directly into the SQL text.
        return stmt.executeQuery("SELECT * FROM invoices WHERE customer = '" + customer + "'");
    }

    public ResultSet findInvoicesByCustomerSafe(HttpServletRequest request) throws SQLException {
        String customer = request.getParameter("customer");
        // Safe: bound parameter via PreparedStatement, no string concat.
        java.sql.PreparedStatement ps = conn.prepareStatement("SELECT * FROM invoices WHERE customer = ?");
        ps.setString(1, customer);
        return ps.executeQuery();
    }

    // --- Command injection: Runtime.exec with concatenated input ----------
    public void generateStatement(HttpServletRequest request) throws IOException {
        String account = request.getParameter("account");
        // Vulnerable: account reaches a shell command built by string
        // concatenation and handed to Runtime.exec's single-string form.
        Runtime.getRuntime().exec("statement-gen.sh --account=" + account);
    }

    public void generateStatementSafe(HttpServletRequest request) throws IOException {
        String account = request.getParameter("account");
        // Safe: argv-array form, no shell string built from untrusted input.
        Runtime.getRuntime().exec(new String[] { "statement-gen.sh", "--account=" + account });
    }

    // --- Path traversal: unchecked File join --------------------------------
    public String readInvoice(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        // Vulnerable: filename is joined onto INVOICES_DIR with no
        // containment check before the file is opened.
        File target = new File(INVOICES_DIR, filename);
        BufferedReader reader = new BufferedReader(new FileReader(target));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) out.append(line);
        return out.toString();
    }

    public String readInvoiceSafe(HttpServletRequest request) throws IOException {
        String filename = request.getParameter("file");
        File target = new File(INVOICES_DIR, filename);
        String canonicalTarget = target.getCanonicalPath();
        String canonicalDir = new File(INVOICES_DIR).getCanonicalPath();
        // Safe: canonical path is checked to still be inside INVOICES_DIR
        // before the file is opened.
        if (!canonicalTarget.startsWith(canonicalDir + File.separator)) {
            throw new IOException("forbidden");
        }
        BufferedReader reader = new BufferedReader(new FileReader(canonicalTarget));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) out.append(line);
        return out.toString();
    }

    // --- Reflected XSS: unescaped concatenation into the response ---------
    public void renderSearchResults(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getParameter("q");
        // Vulnerable: query is written into the HTML response with no
        // encoding.
        response.getWriter().write("<div>Results for: " + query + "</div>");
    }

    public void renderSearchResultsSafe(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String query = request.getParameter("q");
        String encoded = org.apache.commons.text.StringEscapeUtils.escapeHtml4(query);
        // Safe: query is HTML-encoded before being written into the response.
        response.getWriter().write("<div>Results for: " + encoded + "</div>");
    }
}
