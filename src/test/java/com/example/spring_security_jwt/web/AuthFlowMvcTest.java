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
class AuthFlowMvcTest {

    @Autowired
    MockMvc mvc;

    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    PasswordEncoder encoder;

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
    void health_is_public() throws Exception {
        mvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().string("ok"));
    }

    @Test
    void me_requires_auth() throws Exception {
        mvc.perform(get("/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void login_then_access_me_and_admin() throws Exception {
        var loginJson = """
                {"username":"admin","password":"1234"}
                """;

        var tokenJson = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(loginJson))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists())
                .andReturn().getResponse().getContentAsString();

        // 매우 단순 파싱(랩용). 실제론 ObjectMapper 쓰자.
        String access = tokenJson.split("\"accessToken\":\"")[1].split("\"")[0];

        mvc.perform(get("/me")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("hello")));

        mvc.perform(get("/admin/ping")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(content().string("admin-ok"));
    }
}
