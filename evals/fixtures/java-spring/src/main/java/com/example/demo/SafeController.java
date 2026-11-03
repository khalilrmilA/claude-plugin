package com.example.demo;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

// Safe-but-suspicious code. A good reviewer reports NOTHING here.
@RestController
public class SafeController {

    private final JdbcTemplate jdbc;

    public SafeController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    // Parameterized query: name is a bound parameter, not concatenated.
    // (Read-only, public product listing — no per-user authorization needed.)
    @GetMapping("/safe/products")
    public Object products(@RequestParam String name) {
        return jdbc.queryForList("SELECT id, title FROM products WHERE title = ?", name);
    }
}
