package com.example.demo;

import java.io.*;
import java.net.URL;
import java.nio.file.*;
import javax.xml.parsers.DocumentBuilderFactory;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;
import org.xml.sax.InputSource;

@RestController
public class ApiController {

    private final JdbcTemplate jdbc;

    public ApiController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // SQL injection: request value concatenated into the query.
    @GetMapping("/users")
    public Object users(@RequestParam String name) {
        return jdbc.queryForList(
            "SELECT id, email FROM users WHERE name = '" + name + "'");
    }

    // Path traversal: user-controlled filename joined to a base directory.
    @GetMapping("/file")
    public byte[] file(@RequestParam String name) throws IOException {
        return Files.readAllBytes(Paths.get("/srv/data/" + name));
    }

    // SSRF: server fetches a user-supplied URL.
    @GetMapping("/fetch")
    public String fetch(@RequestParam String url) throws IOException {
        try (InputStream in = new URL(url).openStream()) {
            return new String(in.readAllBytes());
        }
    }

    // XXE: external entities not disabled on the XML parser.
    @PostMapping("/xml")
    public String xml(@RequestBody String body) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        var doc = f.newDocumentBuilder().parse(new InputSource(new StringReader(body)));
        return doc.getDocumentElement().getNodeName();
    }

    // Insecure deserialization of untrusted bytes.
    @PostMapping("/obj")
    public Object obj(@RequestBody byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();
    }

    // Missing authorization: deletes any user; no role or ownership check.
    @DeleteMapping("/users/{id}")
    public void delete(@PathVariable long id) {
        jdbc.update("DELETE FROM users WHERE id = ?", id);
    }
}
