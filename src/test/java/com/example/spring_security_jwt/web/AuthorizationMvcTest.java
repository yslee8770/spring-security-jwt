package com.example.spring_security_jwt.web;

import com.example.spring_security_jwt.security.JwtTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationMvcTest {

    @Autowired MockMvc mvc;
    @Autowired JwtTokenService tokenService;

    @Test
    void user_role_cannot_access_admin_403() throws Exception {
        String access = tokenService.mint(1L, "user", new String[]{"ROLE_USER"}).accessToken();

        mvc.perform(get("/admin/ping")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    void admin_role_can_access_admin_200() throws Exception {
        String access = tokenService.mint(2L, "admin", new String[]{"ROLE_ADMIN"}).accessToken();

        mvc.perform(get("/admin/ping")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk());
    }

    @Test
    void missing_permission_denies_method_security_403() throws Exception {
        // PERM_REPORT_READ 없이 호출 -> @PreAuthorize가 403을 만들어야 함
        String access = tokenService.mint(3L, "user", new String[]{"ROLE_USER"}).accessToken();

        mvc.perform(get("/reports/summary")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isForbidden())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));
    }

    @Test
    void having_permission_allows_method_security_200() throws Exception {
        String access = tokenService.mint(4L, "user", new String[]{"ROLE_USER", "PERM_REPORT_READ"}).accessToken();

        mvc.perform(get("/reports/summary")
                        .header("Authorization", "Bearer " + access))
                .andExpect(status().isOk())
                .andExpect(content().string("report-ok"));
    }
}
