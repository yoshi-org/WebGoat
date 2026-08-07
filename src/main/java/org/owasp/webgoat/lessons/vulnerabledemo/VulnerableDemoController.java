package org.owasp.webgoat.lessons.vulnerabledemo;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.stream.Collectors;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnerableDemoController {

  // VULN: SQL Injection - java/sql-injection
  @GetMapping("/demo/users/search")
  public String searchUsers(@RequestParam String username) throws Exception {
    Connection conn = DriverManager.getConnection("jdbc:hsqldb:mem:demodb", "sa", "");
    Statement stmt = conn.createStatement();
    String query = "SELECT * FROM users WHERE username = '" + username + "'";
    ResultSet rs = stmt.executeQuery(query);
    StringBuilder sb = new StringBuilder();
    while (rs.next()) {
      sb.append(rs.getString(1)).append("\n");
    }
    rs.close();
    stmt.close();
    conn.close();
    return sb.toString();
  }

  // VULN: Cross-Site Scripting (Reflected XSS) - java/xss
  @GetMapping("/demo/greet")
  public void greetUser(@RequestParam String name, HttpServletResponse response) throws Exception {
    response.setContentType("text/html");
    response.getWriter().println("<h1>Hello, " + name + "</h1>");
  }

  // VULN: Code Injection (Script Injection) - java/script-injection
  @GetMapping("/demo/calculate")
  public String calculate(@RequestParam String expression) throws Exception {
    ScriptEngine engine = new ScriptEngineManager().getEngineByName("JavaScript");
    Object result = engine.eval(expression);
    return "Result: " + result;
  }

  // VULN: Path Traversal - java/path-injection
  @GetMapping("/demo/files/read")
  public String readFile(@RequestParam String filename) throws Exception {
    File file = new File("/var/data/uploads/" + filename);
    byte[] content = Files.readAllBytes(file.toPath());
    return new String(content);
  }

  // VULN: Server-Side Request Forgery (SSRF) - java/ssrf
  @GetMapping("/demo/fetch")
  public String fetchUrl(@RequestParam String url) throws Exception {
    URL targetUrl = new URL(url);
    HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();
    conn.setRequestMethod("GET");
    InputStream stream = conn.getInputStream();
    String body = new BufferedReader(new InputStreamReader(stream))
        .lines().collect(Collectors.joining("\n"));
    stream.close();
    conn.disconnect();
    return body;
  }
}
