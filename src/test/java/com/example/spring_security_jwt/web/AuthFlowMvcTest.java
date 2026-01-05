package com.example.spring_security_jwt.web;

import com.example.spring_security_jwt.domain.AppUser;
import com.example.spring_security_jwt.domain.Role;
import com.example.spring_security_jwt.repository.RoleRepository;
import com.example.spring_security_jwt.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

    @Autowired MockMvc mvc;
    @Autowired UserRepository userRepository;
    @Autowired RoleRepository roleRepository;
    @Autowired PasswordEncoder encoder;

    private final ObjectMapper om = new ObjectMapper();

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
        roleRepository.deleteAll();

        Role adminRole = roleRepository.save(new Role("ROLE_ADMIN"));
        Role userRole  = roleRepository.save(new Role("ROLE_USER"));

        AppUser admin = new AppUser("admin", encoder.encode("1234"));
        admin.addRole(adminRole);
        userRepository.save(admin);

        AppUser user = new AppUser("user", encoder.encode("1234"));
        user.addRole(userRole);
        userRepository.save(user);
    }

    @Test
    void health_is_public() throws Exception {
        mvc.perform(get("/health"))
                .andExpect(status().isOk())
                .andExpect(content().string("ok"));
    }

    @Test
    void me_unauthenticated_returns_401_json() throws Exception {
        mvc.perform(get("/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void admin_unauthenticated_returns_401_json() throws Exception {
        mvc.perform(get("/admin/ping"))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    }

    @Test
    void admin_authenticated_but_not_authorized_returns_403_json() throws Exception {
        String access = loginAndGetAccessToken("user", "1234");

        mvc.perform(get("/admin/ping")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    void admin_login_then_access_me_and_admin_ok() throws Exception {
        String access = loginAndGetAccessToken("admin", "1234");

        mvc.perform(get("/me")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("hello")));

        mvc.perform(get("/admin/ping")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(content().string("admin-ok"));
    }

    private String loginAndGetAccessToken(String username, String password) throws Exception {
        String body = """
                {"username":"%s","password":"%s"}
                """.formatted(username, password);

        String resp = mvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.accessToken").exists())
                .andReturn().getResponse().getContentAsString();

        JsonNode json = om.readTree(resp);
        return json.get("accessToken").asText();
    }
}
