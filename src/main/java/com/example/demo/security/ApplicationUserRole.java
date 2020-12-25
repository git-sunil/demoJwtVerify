package com.example.demo.security;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

import static com.example.demo.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(new HashSet<>(Arrays.asList())),
    ADMIN(new HashSet<>(Arrays.asList(COURSE_READ,
            COURSE_WRITE,
            STUDENT_READ,
            STUDENT_WRITE))),
    ADMINTRAINEE(new HashSet<>(Arrays.asList(COURSE_READ,STUDENT_READ)));

    private final Set<ApplicationUserPermission> permissions;
    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }

    public Set<SimpleGrantedAuthority> getGrantedAuthorities(){
        Set<SimpleGrantedAuthority> permissions = this.permissions
                .stream()
                .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
                .collect(Collectors.toSet());
        permissions.add(new SimpleGrantedAuthority("ROLE_"+this.name()));
        return permissions;
    }
}
