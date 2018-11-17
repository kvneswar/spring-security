package com.example.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
            .inMemoryAuthentication()
            .withUser("user").password(passwordEncoder().encode("password")).roles("USER")
            .and()
            .withUser("admin").password(passwordEncoder().encode("password")).roles("ADMIN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .authorizeRequests()
                .antMatchers("/login*").permitAll()
                .antMatchers("/admin*").hasRole("ADMIN")
                .antMatchers("/**").hasRole("USER")
                .anyRequest().authenticated()
            .and()
                .formLogin()
                    .loginPage("/login.html")
                    .loginProcessingUrl("/authenticate_user")
                    .defaultSuccessUrl("/home.html")
                    .failureForwardUrl("/login.html")
            .and()
                .logout()
                    .logoutUrl("/logout_user")
                    .logoutSuccessUrl("/login.html")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
            .and()
                .rememberMe()
                    .key("uniqueAndSecret")
                    .tokenValiditySeconds(86_400)
                    .rememberMeParameter("remember-me-new");
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
            return new BCryptPasswordEncoder();
        }

}
