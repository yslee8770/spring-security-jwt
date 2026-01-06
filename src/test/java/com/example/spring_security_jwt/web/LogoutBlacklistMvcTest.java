package com.example.spring_security_jwt.web;

import com.example.spring_security_jwt.domain.AppUser;
import com.example.spring_security_jwt.domain.Role;
import com.example.spring_security_jwt.repository.RoleRepository;
import com.example.spring_security_jwt.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class LogoutBlacklistMvcTest {

    @Autowired MockMvc mvc;
    @Autowired UserRepository userRepository;
    @Autowired RoleRepository roleRepository;
    @Autowired PasswordEncoder encoder;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        roleRepository.deleteAll();

        AppUser user = new AppUser("admin", encoder.encode("1234"));
        Role adminRole = roleRepository.save(new Role("ROLE_ADMIN"));
        user.addRole(adminRole);
        userRepository.save(user);
    }

    @Test
    void logout_then_same_access_token_is_rejected_401() throws Exception {
        // login
        String loginJson = """
                {"username":"admin","password":"1234"}
                """;

        String tokenJson = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andReturn().getResponse().getContentAsString();

        String access = tokenJson.split("\"accessToken\":\"")[1].split("\"")[0];

        mvc.perform(get("/me")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("hello")));

        mvc.perform(post("/auth/logout")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());

        mvc.perform(get("/me")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isUnauthorized());
    }
}
