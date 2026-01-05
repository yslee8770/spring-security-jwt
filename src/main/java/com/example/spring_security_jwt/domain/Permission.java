package com.example.spring_security_jwt.domain;

import jakarta.persistence.*;
import lombok.Getter;

@Entity
@Getter
@Table(name = "permission")
public class Permission {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true, length = 80)
    private String name;

    protected Permission() { }
    public Permission(String name) { this.name = name; }
}
