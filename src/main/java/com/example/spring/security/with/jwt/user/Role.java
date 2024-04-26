package com.example.spring.security.with.jwt.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.spring.security.with.jwt.user.Permission.*;

@RequiredArgsConstructor
public enum Role {

    MEMBER(
            Set.of(
                    MEMBER_READ,
                    MEMBER_CREATE
            )
    ),
    ADMIN(
            Set.of(
                    ADMIN_READ,
                    ADMIN_CREATE,
                    MEMBER_READ,
                    MEMBER_CREATE
            )
    );

    @Getter
    private final Set<Permission> permissions;

    public List<SimpleGrantedAuthority> getAuthorities(){
        var authorities=getPermissions()
                .stream()
                .map(authority ->new SimpleGrantedAuthority(authority.getPermission()))
                .collect(Collectors.toList());
        authorities.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return authorities;

    }

}
