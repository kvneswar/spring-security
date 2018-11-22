package com.example.oauth2login;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class Oauth2LoginApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2LoginApplication.class, args);
    }
}

@RestController
class TestController{

    @GetMapping
    public Authentication authentication(Authentication authentication){
        return authentication;
    }
}