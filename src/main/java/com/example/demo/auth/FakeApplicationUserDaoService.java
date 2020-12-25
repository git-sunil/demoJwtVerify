package com.example.demo.auth;

import com.example.demo.security.ApplicationUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import static com.example.demo.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUserName(String userName) {
        return getApplicationUsers()
                .stream()
                .filter(user->user.getUsername().equals(userName))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = new ArrayList<>(Arrays.asList(
               new ApplicationUser(
                       STUDENT.getGrantedAuthorities(),
                       "annasmith",
                       passwordEncoder.encode("password"),
                       true,true,true,true),
                new ApplicationUser(
                       ADMIN.getGrantedAuthorities(),
                       "linda",
                       passwordEncoder.encode("password12"),
                       true,true,true,true),
                new ApplicationUser(
                       ADMINTRAINEE.getGrantedAuthorities(),
                       "tom",
                       passwordEncoder.encode("password123"),
                       true,true,true,true)

        ));
        return applicationUsers;
    }
}
