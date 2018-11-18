package com.example.demo;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    UserDetailsService userDetailsService(){
        return new InMemoryUserDetailsManager();
    }

    @Bean
    InitializingBean initialize(UserDetailsManager userDetailsManager){
        return ()->{
            UserDetails eswarDetails = User.withDefaultPasswordEncoder().username("ekarumuri").password("password").roles("USER").build();
            userDetailsManager.createUser(eswarDetails);
        };
    }

}
