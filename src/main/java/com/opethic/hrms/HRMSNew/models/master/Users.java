package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;

@Data
@Entity
@Table(name = "users_tbl")
public class Users{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String usercode;
    private String username;
    private String userRole;
    private String fullName;
    private Long mobileNumber;
    private String emailId;
    private String address;
    private String gender;
    private String password;
    private String plainPassword;
    private Boolean isSuperAdmin;
    private String permissions;
    private Boolean isAdmin;
    private Boolean status;
    @Column(insertable = false)
    @UpdateTimestamp
    private LocalDateTime lastLogin;
    private Long createdBy;
    @Column(updatable = false)
    @CreationTimestamp
    private LocalDateTime createdAt;
    @Column(insertable = false)
    @UpdateTimestamp
    private LocalDateTime updatedAt;
    private Long updatedBy;

    @ManyToOne
    @JoinColumn(name = "company_id")
    @JsonManagedReference
    private Company company;

    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;

    @ManyToOne
    @JoinColumn(name = "role_id")
    @JsonManagedReference
    private Role role;
}
