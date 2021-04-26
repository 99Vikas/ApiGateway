package com.railway.apigateway.Security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.HttpMethod;

@EnableWebSecurity
public class SecurityTokenConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    JWTConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.POST, jwtConfig.getUri()).permitAll()
                //TODO Add search antMatchers
                .antMatchers("/customer/**").hasAnyRole("ADMIN", "USER")
//                //TODO divide controllers base on roles in services
                .antMatchers("/customer/admin/**").hasRole("ADMIN")
                .antMatchers("/train/**").hasAnyRole("ADMIN", "USER")
                .antMatchers("/train/admin/**").hasRole("ADMIN")
                .antMatchers("/booking/**").hasAnyRole("ADMIN", "USER")
                .antMatchers("/booking/admin/**").hasRole("ADMIN")
                .anyRequest()
                .authenticated()
                .and()
                .addFilterAfter(new JWTAuthenticationFilter(jwtConfig), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public JWTConfig jwtConfig() {
        return new JWTConfig();
    }
}