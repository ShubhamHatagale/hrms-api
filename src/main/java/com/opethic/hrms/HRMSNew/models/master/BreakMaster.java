package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.Data;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDateTime;
import java.time.LocalTime;

@Data
@Entity
@Table(name = "break_master_tbl")
public class BreakMaster {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String breakName;
    private LocalTime fromTime;
    private LocalTime toTime;
    private Boolean isBreakPaid;
    private Boolean status;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Long updatedBy;
    private LocalDateTime updatedAt;
    @ManyToOne
    @JoinColumn(name = "branch_id")
    @JsonManagedReference
    private Branch branch;

    @ManyToOne
    @JoinColumn(name = "company_id")
    @JsonManagedReference
    private Company company;
}
