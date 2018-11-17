package com.example.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping
    @PreAuthorize("hasAuthority('READ_PRIVILEGE')")
    public String testApi(){
        return "Hello, World!!!";
    }

}
