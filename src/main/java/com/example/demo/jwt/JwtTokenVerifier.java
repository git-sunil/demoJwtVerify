package com.example.demo.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.apache.logging.log4j.util.Strings;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader("Authorization");
        if(Strings.isEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
        String key = "securesecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecuresecure";
        String token = authorizationHeader.replace("Bearer ","");
        try {
            Jws<Claims> claimsJws = Jwts
                    .parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(key.getBytes()))
                    .build()
                    .parseClaimsJws(token);
            Claims claims = claimsJws.getBody();
            String userName = claims.getSubject();
            List<Map<String,String>> authorities = (List<Map<String,String>>)claims.get("authorities");
            Set<SimpleGrantedAuthority> simpleAuthority = authorities.stream().map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    userName,
                    null,
                    simpleAuthority
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);

        }catch (JwtException e){
            throw new IllegalStateException(String.format("Token %s can't be trusted.",token));
        }
        filterChain.doFilter(request,response);
    }
}
