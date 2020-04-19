package com.example;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;
import java.util.Arrays;

@SpringBootApplication
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }

}

@Configuration
class SpringSecurityConfiguration extends WebSecurityConfigurerAdapter {

    /*@Autowired
    private DataSource dataSource;

   @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication()
                .dataSource(dataSource)
                .usersByUsernameQuery("SELECT USERNAME, PASSWORD, ENABLED FROM USERS WHERE USERNAME = ?")
                .authoritiesByUsernameQuery("SELECT USERNAME, AUTHORITY FROM AUTHORITIES WHERE USERNAME = ?")
                .passwordEncoder(new BCryptPasswordEncoder());       
    }*/

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/admin").hasRole("ADMIN")
                .antMatchers("/**").permitAll()
                .anyRequest().authenticated()
            .and()
                .httpBasic()
            .and()
                .headers().frameOptions().disable()
            .and()
                .csrf().disable();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }
}

@Component
@Slf4j
class CustomUserDetailsService implements UserDetailsService{

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        User user = jdbcTemplate.query("select u.username, u.password, u.enabled, a.authority from users u join authorities a on u.username = a.username where u.username = ?", ps -> {
                ps.setString(1, username);
            }, rs -> {
            	User user1 = null;
            	while(rs.next()) {
            		user1 = new User(
                            rs.getString("username"),
                            rs.getString("password"),
                            rs.getBoolean("enabled"),
                            rs.getBoolean("enabled"),
                            rs.getBoolean("enabled"),
                            rs.getBoolean("enabled"),
                            Arrays.asList(new SimpleGrantedAuthority(rs.getString("authority")))
                        );
            		break;
            	}
            return user1;
        });

        log.info("user: {}", user);
        if(user == null){
            throw new UsernameNotFoundException(username + " is not found");
        }
        return user;
    }

}


@RestController
class SampleController{

    @GetMapping(value = {"/user", "/admin"})
    public String greetings(){
        return "Hello, World!!!";
    }
}