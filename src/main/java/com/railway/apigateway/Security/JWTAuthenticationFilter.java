package com.railway.apigateway.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;


public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JWTConfig jwtConfig;

    public JWTAuthenticationFilter(JWTConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }
    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String header = httpServletRequest.getHeader(jwtConfig.getHeader());
        System.out.println(header);
        if (header == null || !header.startsWith(jwtConfig.getPrefix())) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }

        String token = header.replace(jwtConfig.getPrefix(), "");

        Claims claims = Jwts.parser()
                .setSigningKey(jwtConfig.getSecret().getBytes())
                .parseClaimsJws(token)
                .getBody();

        System.out.println(claims);

        String userEmail = claims.getSubject();
        System.out.println(userEmail);
        if (userEmail != null) {
            List<String> authorities = (List<String>) claims.get("authorities");
            System.out.println(authorities );
            UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(userEmail, null, authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}