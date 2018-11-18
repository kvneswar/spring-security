package com.example;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

import javax.sql.DataSource;

@SpringBootApplication
public class SpringSecurityFromloginDbApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityFromloginDbApplication.class, args);
    }

    @Bean
    UserDetailsManager userDetailsManager(DataSource dataSource){
        JdbcUserDetailsManager jdbcUserDetailsManager = new JdbcUserDetailsManager();
        jdbcUserDetailsManager.setDataSource(dataSource);
        return jdbcUserDetailsManager;
    }

    @Bean
    InitializingBean initializer(UserDetailsManager userDetailsManager){
        return ()->{
            UserDetails eswarDetails = User.withDefaultPasswordEncoder().username("ekarumuri").password("password").roles("USER").build();
            userDetailsManager.createUser(eswarDetails);
        };
    }
}

