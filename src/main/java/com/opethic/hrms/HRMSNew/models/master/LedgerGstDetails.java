package com.opethic.hrms.HRMSNew.models.master;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.time.LocalDate;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "ledger_gst_details_tbl")
public class LedgerGstDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String gstin;
    private LocalDate dateOfRegistration;
    private String stateCode;
    private String panCard;
    private Long createdBy;
    @CreationTimestamp
    private LocalDateTime createdAt;
    private Boolean status;
    @ManyToOne
    @JoinColumn(name = "ledger_id")
    @JsonManagedReference
    private LedgerMaster ledgerMaster;

}

