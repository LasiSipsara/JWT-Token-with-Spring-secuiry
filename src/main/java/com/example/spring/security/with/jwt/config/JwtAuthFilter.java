package com.example.spring.security.with.jwt.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal
            (@NonNull HttpServletRequest request,
             @NonNull HttpServletResponse response,
             @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        //verify whether request has authorization header, and it has bearer
        final String authHeader=request.getHeader("Authorization");
        String jwt;
        String email;
        if(authHeader==null||!authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }

        //Extract  jwt from the authorization
        jwt=authHeader.substring(7);
        //verify whether user is present in db
        //verify whether token is valid
        email= jwtService.extractUsername(jwt);
        //if user is present and no authentication object in securityContext
        if(email!=null && SecurityContextHolder.getContext().getAuthentication()==null){
            //if valid set to security context holder

            UserDetails userDetails=this.userDetailsService.loadUserByUsername(email);
            UsernamePasswordAuthenticationToken authToken= new UsernamePasswordAuthenticationToken(
                    userDetails,
                    null,
                    userDetails.getAuthorities()
            );
            SecurityContextHolder.getContext().setAuthentication(authToken);
        }

    filterChain.doFilter(request,response);

    }










    //verify if it is whitelisted path and if yes do not do anything
    @Override
    protected boolean shouldNotFilter(@NonNull  HttpServletRequest request) throws ServletException {
        return request.getServletPath().contains("/crackit/v1/auth");
    }

}
