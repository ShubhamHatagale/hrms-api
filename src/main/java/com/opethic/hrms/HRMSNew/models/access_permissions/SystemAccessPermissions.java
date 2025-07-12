package com.opethic.hrms.HRMSNew.models.access_permissions;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.master.Role;
import com.opethic.hrms.HRMSNew.models.master.Users;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "access_permissions_tbl")
public class SystemAccessPermissions {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "users_id")
    @JsonManagedReference
    private Users users;

    @ManyToOne
    @JoinColumn(name = "role_id")
    @JsonManagedReference
    private Role userRole;

    @ManyToOne
    @JoinColumn(name = "action_mapping_id")
    @JsonManagedReference
    private SystemActionMapping systemActionMapping;

    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Boolean status;
    private String userActionsId;//System Master Actions Id

}
