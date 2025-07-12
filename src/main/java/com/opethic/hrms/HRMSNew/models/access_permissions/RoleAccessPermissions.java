package com.opethic.hrms.HRMSNew.models.access_permissions;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.opethic.hrms.HRMSNew.models.master.Role;
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
@Table(name = "role_access_permissions_tbl")
public class RoleAccessPermissions {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "role_id")
    @JsonManagedReference
    private Role roleMaster;

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
